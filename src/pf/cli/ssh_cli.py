import base64
import getpass
import os
import tempfile
import time

from .. import client, jwk, ssh


def _refresh_known_hosts(auth, known_hosts):
    known_hosts = os.path.abspath(os.path.expanduser(known_hosts))
    now = int(time.time())
    try:
        st = os.stat(known_hosts)
        if st.st_mtime + 60 > now:
            # We do not refresh known hosts more often than once every 60s
            return
    except FileNotFoundError:
        pass
    host_trusted_keys_response = auth.get(f"{auth.directory.ssh}/host/trusted-keys")
    if host_trusted_keys_response.status_code != 200:
        raise client.exceptions.UI(host_trusted_keys_response.json()["title"])
    with open(known_hosts, "wb+") as f:
        for line in host_trusted_keys_response.content.split(b"\n"):
            f.write(line)


def _has_valid_session(c: client.Config) -> bool:
    if not c.session_key:
        return False
    try:
        agent = ssh.agent.Client()
        for identity in agent.list_identities():
            if identity.public_key.match_ssh_fingerprint(c.session_key):
                return True
    except Exception:
        pass
    return False


@client.ssh_utils.exception
def _ssh_function(args):
    c = client.Config.load(args.config)

    # Auto-login for http_sig only; other auth types require pf login first
    if not _has_valid_session(c):
        api = client.Client(c)
        response = api.no_auth.get(f"{api.directory.auth}/default")
        if response.status_code != 200:
            raise client.exceptions.UI("Not logged in. Run 'pf login' first.")
        auth_public = response.json()
        match auth_public["type"]:
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
                raise client.exceptions.UI(f"Session expired. Run 'pf login' first (auth type: {auth_public['type']}).")

    destination = args.destination
    if "@" in destination:
        user, host = destination.split("@", 1)
    else:
        user = getpass.getuser()
        host = destination

    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    user_key = jwk.Private.generate_ed25519()
    cert_response = auth.post(
        f"{auth.directory.ssh}/user/certificate",
        json={
            "public_key": user_key.public().to_dict(),
            "hostname": host,
            "username": user,
            "action": "shell",
        },
    )
    if cert_response.status_code == 403:
        raise client.exceptions.UI(f"Permission denied: cannot connect as {user}@{host}")
    if cert_response.status_code != 200:
        raise client.exceptions.UI(cert_response.json()["title"])

    try:
        ssh_agent = ssh.agent.Client()
    except Exception:
        raise client.exceptions.UI("Unable to connect to user's SSH agent")

    for certificate in cert_response.json()["certificates"]:
        cert = ssh.cert.Cert.from_openssh(base64.b64decode(certificate))
        ssh_agent.add(user_key, cert=cert, comment=host, lifetime=60)

    # Write public key to temp file so ssh picks this exact key from the agent.
    # File left in /tmp after exec (public key only, not sensitive).
    pubkeyfd, pubkeyfile = tempfile.mkstemp(suffix=".pub")
    with os.fdopen(pubkeyfd, "wb") as f:
        f.write(user_key.public().to_openssh())

    _refresh_known_hosts(auth, args.known_hosts)

    ssh_cmd = ["ssh", "-i", pubkeyfile, "-o", "IdentitiesOnly=yes", *args.ssh_args, destination]
    os.execvp("ssh", ssh_cmd)


def add_subparser(subparsers):
    ssh_parser = subparsers.add_parser("ssh", help="Login, get certificate, and connect via SSH")
    ssh_parser.add_argument("destination", help="[user@]hostname (pf identity name of the host)")
    ssh_parser.add_argument("ssh_args", nargs="*", help="Additional arguments passed to ssh")
    ssh_parser.add_argument("--known-hosts", help="Known hosts file to refresh", default="~/.ssh/known_hosts")
    ssh_parser.set_defaults(func=_ssh_function)
