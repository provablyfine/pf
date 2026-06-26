import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile

from ... import client, jwk, ssh


def _write_file_atomic(filepath: str, content: bytes | str, mode: str = "wb") -> None:
    dirname = os.path.dirname(filepath) or "."
    os.makedirs(dirname, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dirname)
    try:
        with os.fdopen(fd, mode) as f:
            f.write(content)
        os.rename(tmp_path, filepath)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def _sign_host_certificates_with_auth(auth_http: client.http_client.HttpClient, host_keys_dir: str) -> None:
    public_keys: list[dict[str, str]] = []
    filename_from_fingerprint: dict[str, str] = {}

    for key_type in ["ed25519", "ecdsa", "rsa"]:
        pubkey_path = os.path.join(host_keys_dir, f"ssh_host_{key_type}_key.pub")
        if not os.path.exists(pubkey_path):
            continue

        with open(pubkey_path, "rb") as f:
            public_key = jwk.Public.from_openssh(f.read())
            public_keys.append(public_key.to_dict())
            filename_from_fingerprint[public_key.ssh_fingerprint()] = pubkey_path

    if not public_keys:
        raise RuntimeError("No SSH host public keys found")

    response = auth_http.post(
        url=auth_http.directory.ssh + "/host/certificate",
        json={"public_keys": public_keys},
    )

    if response.status_code != 200:
        raise RuntimeError(f"Failed to sign host certificates: {response.text}")

    for certificate in response.json().get("certificates", []):
        openssh_cert = base64.b64decode(certificate)
        cert = ssh.cert.Cert.from_openssh(openssh_cert)
        pubkey_path = filename_from_fingerprint[cert.public_key.ssh_fingerprint()]
        cert_path = pubkey_path.rstrip(".pub") + ".cert"
        _write_file_atomic(cert_path, openssh_cert + b"\n", mode="wb")


def _do_refresh(
    account_key: jwk.Private,
    directory_url: str,
    host_keys_dir: str,
    ca_pub_path: str,
) -> None:
    """Shared refresh logic: sign certs, fetch CA pubkey, reload sshd."""
    session_key = jwk.Private.generate_ed25519()

    config = client.configuration.Config(directory_url=directory_url)
    factory = client.Factory(config)

    factory.account_from_keys(account_key, session_key).login_http_sig(session_key.public().to_dict())

    http = client.http_client.Client(config)
    _sign_host_certificates_with_auth(http.session_auth_with_key(session_key), host_keys_dir)

    ca_pubkey = factory.public().get_user_trusted_keys_public()
    _write_file_atomic(ca_pub_path, ca_pubkey, mode="w")


def _print_init_script(
    account_key: jwk.Private,
    directory_url: str,
    host_keys_dir: str,
    ca_pub_path: str,
    sshd_config_drop_in: str,
    auth_user: str,
) -> None:
    account_key_b64 = base64.b64encode(account_key.to_openssh()).decode()
    config_json = json.dumps(
        {
            "directory_url": directory_url,
            "account_key_file": "$CREDENTIALS_DIRECTORY/account",
        }
    )
    sshd_drop_in_dir = os.path.dirname(sshd_config_drop_in)
    refresh_cmd = (
        f"pf openssh host-refresh"
        f" --config=/var/lib/pf/config.json"
        f" --host-keys-dir={host_keys_dir}"
        f" --ca-pub-path={ca_pub_path}"
    )
    refresh_service = "\n".join(
        [
            "[Unit]",
            "Description=Provably Fine SSH host certificate refresh",
            "",
            "[Service]",
            "Type=oneshot",
            f"ExecStart={refresh_cmd}",
            "LoadCredential=account:/var/lib/pf/account.cred",
        ]
    )
    refresh_timer = "\n".join(
        [
            "[Unit]",
            "Description=Provably Fine SSH host certificate refresh timer",
            "",
            "[Timer]",
            "OnCalendar=daily",
            "Persistent=true",
            "",
            "[Install]",
            "WantedBy=timers.target",
        ]
    )
    lines = [
        "#!/bin/sh",
        "set -eu",
        "",
        "for _pf_d in TrustedUserCAKeys AuthorizedPrincipalsCommand; do",
        f'  if grep -rqE "^${{_pf_d}}" /etc/ssh/sshd_config {sshd_drop_in_dir}/ 2>/dev/null; then',
        "    echo \"conflicting sshd directive '$_pf_d' found; remove before initializing pf\" >&2",
        "    exit 1",
        "  fi",
        "done",
        "",
        "install -d -m 700 /var/lib/pf",
        f"printf '%s' '{account_key_b64}' | base64 -d | systemd-creds encrypt - /var/lib/pf/account.cred",
        "",
        "cat > /var/lib/pf/config.json << 'PFEOF'",
        config_json,
        "PFEOF",
        "",
        "ssh-keygen -A",
        refresh_cmd,
        "",
        f"install -d -m 755 {sshd_drop_in_dir}",
        "{",
        f"  echo 'TrustedUserCAKeys {ca_pub_path}'",
        f"  for cert in {host_keys_dir}/ssh_host_*_key.cert; do",
        '    [ -f "$cert" ] && echo "HostCertificate $cert"',
        "  done",
        f"  echo 'AuthorizedPrincipalsCommand /usr/bin/pf openssh auth-principals"
        f" --host-certificate={host_keys_dir}/ssh_host_ed25519_key.cert --username=%u --certificate=%k'",
        f"  echo 'AuthorizedPrincipalsCommandUser {auth_user}'",
        "  echo 'PubkeyAuthentication yes'",
        f"}} > {sshd_config_drop_in}",
        "",
        "cat > /etc/systemd/system/pf-host-refresh.service << 'PFEOF'",
        refresh_service,
        "PFEOF",
        "",
        "cat > /etc/systemd/system/pf-host-refresh.timer << 'PFEOF'",
        refresh_timer,
        "PFEOF",
        "",
        "systemctl daemon-reload",
        "systemctl enable --now pf-host-refresh.timer",
        "systemctl reload sshd",
    ]
    sys.stdout.write("\n".join(lines) + "\n")


def host_init_daemon_function(args: argparse.Namespace) -> None:
    """Accept invitation and print a shell script to stdout that sets up pf on this host."""

    directory_url = args.tenant_url or "https://pf.provablyfine.net/pf/directory"

    account_key = jwk.Private.generate_ed25519()

    config = client.configuration.Config(directory_url=directory_url)
    http = client.http_client.Client(config)
    auth = http.invitation_auth_with_key(account_key, args.invitation)
    response = auth.post(
        url=auth.directory.accept_invitation,
        json={"account_public_key": auth.account_public_key.to_dict()},
    )
    if response.status_code != 204:
        raise RuntimeError(f"Failed to accept invitation: {response.text}")

    _print_init_script(
        account_key,
        directory_url,
        args.host_keys_dir,
        args.ca_pub_path,
        args.sshd_config_drop_in,
        args.auth_user,
    )


def host_refresh_function(args: argparse.Namespace) -> None:
    """Refresh host SSH certificates and CA public key."""

    c = client.configuration.Config.load(args.config)

    account_key_file = c.account_key_file or ""
    if account_key_file and "$" in account_key_file:
        account_key_file = os.path.expandvars(account_key_file)

    with open(account_key_file, "rb") as f:
        account_key = client.ssh_utils.load_private_key(f.read())

    _do_refresh(account_key, c.directory_url, args.host_keys_dir, args.ca_pub_path)

    subprocess.run(["/usr/bin/systemctl", "reload", "sshd"], check=True, capture_output=True)
