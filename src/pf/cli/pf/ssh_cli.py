import argparse
import base64
import getpass
import os
import tempfile

from ... import client, jwk, ssh
from .. import login


@client.ssh_utils.exception
def _ssh_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)

    destination = args.destination
    if "@" in destination:
        user, host = destination.split("@", 1)
    elif args.login_user:
        user, host = args.login_user, destination
    else:
        user = getpass.getuser()
        host = destination
    destination = f"{user}@{host}"

    # Auto-login for http_sig only; other auth types require pf login first
    if not login.has_valid_session(c):
        api = client.Client(c, timeout=args.timeout)
        response = api.no_auth.get(f"{api.directory.public_auth}/default")
        if response.status_code != 200:
            raise client.exceptions.UI("Not logged in. Run 'pf login' first.")
        auth_public = response.json()
        match auth_public["config"]["type"]:
            case "http_sig":
                try:
                    ssh_agent = ssh.agent.Client()
                except Exception:
                    raise client.exceptions.UI("Unable to connect to user's SSH agent")
                session_key = jwk.Private.generate_ed25519()
                ssh_agent.add(session_key, comment="pf-session", lifetime=1800)
                c.session_key = session_key.public().ssh_fingerprint()
                login_auth = api.login_auth(account=c.account_key, session=c.session_key)
                resp = login_auth.post(
                    url=login_auth.directory.login,
                    json={"session_public_key": session_key.public().to_dict()},
                )
                if resp.status_code != 204:
                    raise client.exceptions.UI(f"Auto-login failed: {resp.text}")
                c.save(args.config)
            case _:
                raise client.exceptions.UI(f"Session expired. Run 'pf login' first (auth type: {auth_public['config']['type']}).")

    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)

    # Fetch and cache host trusted keys in config
    host_trusted_keys_response = auth.get(f"{auth.directory.ssh}/host/trusted-keys")
    if host_trusted_keys_response.status_code != 200:
        raise client.exceptions.UI(host_trusted_keys_response.json()["title"])
    c.known_hosts = host_trusted_keys_response.content.decode("utf-8")
    c.save(args.config)

    action = "port-forwarding" if (args.forward_local or args.forward_remote) else "shell"
    user_key = jwk.Private.generate_ed25519()
    cert_request = {
        "public_key": user_key.public().to_dict(),
        "hostname": host,
        "username": user,
        "action": action,
    }
    cert_response = auth.post(f"{auth.directory.ssh}/user/certificate", json=cert_request)
    if cert_response.status_code == 403 and action == "shell" and args.command:
        cert_response = auth.post(
            f"{auth.directory.ssh}/user/certificate",
            json={**cert_request, "action": "command", "command": args.command},
        )
    if cert_response.status_code == 403:
        raise client.exceptions.UI("User is not authorized to connect to host")
    elif cert_response.status_code != 200:
        raise client.exceptions.UI(cert_response.json()["title"])

    cert_data = cert_response.json()
    certificates = cert_data["certificates"]
    assert len(certificates) == 1
    bastion_list = cert_data.get("bastion_list", [])
    ip_address_list = cert_data.get("ip_address_list", [])

    try:
        ssh_agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to user's SSH agent")

    ssh_agent.add(user_key, comment=host, lifetime=60)

    decoded = base64.b64decode(certificates[0])
    certfd, certfile = tempfile.mkstemp(suffix=".cert")
    with os.fdopen(certfd, "wb") as f:
        f.write(decoded)

    pubkeyfd, pubkeyfile = tempfile.mkstemp(suffix=".pub")
    with os.fdopen(pubkeyfd, "wb") as f:
        f.write(user_key.public().to_openssh())
        f.write(b"\n")

    khfd, khfile = tempfile.mkstemp(suffix=".known_hosts")
    with os.fdopen(khfd, "wb") as f:
        f.write(c.known_hosts.encode("utf-8") if c.known_hosts else b"")

    def build_ssh_cmd(
        target_host: str,
        proxy_command: str | None = None,
        proxy_jump: str | None = None,
        ip_address: str | None = None,
    ) -> list[str]:
        cmd = [
            "ssh",
            "-F",
            "none",
            "-o",
            f"UserKnownHostsFile={khfile}",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"CertificateFile={certfile}",
            "-o",
            f"IdentityFile={pubkeyfile}",
            "-o",
            "IdentitiesOnly=yes",
        ]
        if args.port:
            cmd += ["-p", args.port]
        for opt in args.ssh_options:
            cmd += ["-o", opt]
        if args.stdin_null:
            cmd += ["-n"]
        for fwd in args.forward_local:
            cmd += ["-L", fwd]
        for fwd in args.forward_remote:
            cmd += ["-R", fwd]
        if proxy_command:
            cmd += ["-o", f"ProxyCommand={proxy_command}"]
        if proxy_jump:
            cmd += ["-o", f"ProxyJump={proxy_jump}"]
        if ip_address:
            cmd += ["-o", f"Hostname={ip_address}", "-o", f"HostKeyAlias={host}"]
        target = f"{user}@{target_host}"
        cmd.append(target)
        if args.command:
            cmd.append(args.command)
        return cmd

    last_error: Exception | None = None

    for bastion in bastion_list:
        if bastion.get("connect_url"):
            connect_url = bastion["connect_url"]
            proxy_cmd = f"pf -c {args.config} bastion connect --url={connect_url} --hostname={host}"
            ssh_cmd = build_ssh_cmd(host, proxy_command=proxy_cmd)
            try:
                os.execvp("/usr/bin/ssh", ssh_cmd)
            except Exception as e:
                last_error = e

        if bastion.get("ssh_proxy_jump"):
            proxy_jump = bastion["ssh_proxy_jump"]
            ssh_cmd = build_ssh_cmd(host, proxy_jump=proxy_jump)
            try:
                os.execvp("/usr/bin/ssh", ssh_cmd)
            except Exception as e:
                last_error = e

    for ip in ip_address_list:
        ssh_cmd = build_ssh_cmd(host, ip_address=ip)
        try:
            os.execvp("/usr/bin/ssh", ssh_cmd)
        except Exception as e:
            last_error = e

    raise client.exceptions.UI(f"Failed to connect via any bastion or direct IP: {last_error}")


def add_subparser(subparsers):
    ssh_parser = subparsers.add_parser("ssh", help="Login, get certificate, and connect via SSH")
    ssh_parser.add_argument(
        "-o",
        dest="ssh_options",
        action="append",
        default=[],
        metavar="OPTION",
        help="SSH option passed through to the underlying ssh command",
    )
    ssh_parser.add_argument("-n", dest="stdin_null", action="store_true", help="Redirect stdin from null")
    ssh_parser.add_argument(
        "-L",
        dest="forward_local",
        action="append",
        default=[],
        metavar="[bind_address:]port:host:hostport",
        help="Local port forwarding",
    )
    ssh_parser.add_argument(
        "-R",
        dest="forward_remote",
        action="append",
        default=[],
        metavar="[bind_address:]port:host:hostport",
        help="Remote port forwarding",
    )
    ssh_parser.add_argument("-l", dest="login_user", default=None, help="Login username")
    ssh_parser.add_argument("-p", dest="port", default=None, help="Port to connect to")
    ssh_parser.add_argument("destination", help="[user@]hostname (pf identity name of the host)")
    ssh_parser.add_argument("command", nargs="?", default=None, help="Command to execute on the remote host")
    ssh_parser.set_defaults(func=_ssh_function)
