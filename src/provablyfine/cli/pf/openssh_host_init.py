import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile

from ... import client, jwk, ssh
from .. import common, login


def _write_file_atomic(filepath: str, content: bytes | str, mode: str = "wb") -> None:
    dirname = os.path.dirname(filepath) or "."
    os.makedirs(dirname, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dirname)
    try:
        with os.fdopen(fd, mode) as f:
            f.write(content)
        os.chmod(tmp_path, 0o644)
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


def _do_refresh(c: client.Config, host_keys_dir: str, ca_pub_path: str) -> None:
    assert c.session_key_pem is not None
    session_key = client.ssh_utils.load_private_key(c.session_key_pem.encode())
    factory = client.Factory(c)
    http = client.http_client.Client(c)
    _sign_host_certificates_with_auth(http.session_auth_with_key(session_key), host_keys_dir)
    ca_pubkey = factory.public().get_user_trusted_keys_public()
    _write_file_atomic(ca_pub_path, ca_pubkey, mode="w")


def _print_init_script(
    invitation: str,
    directory_url: str,
    host_keys_dir: str,
    ca_pub_path: str,
    sshd_config_drop_in: str,
    auth_user: str,
) -> None:
    sshd_drop_in_dir = os.path.dirname(sshd_config_drop_in)
    config_json = json.dumps(
        {
            "directory_url": directory_url,
            "account_key_file": "$CREDENTIALS_DIRECTORY/account",
        }
    )
    sys.stdout.write(f"""\
#!/bin/sh
set -eu

_pf_bin=''
for _d in /usr/local/bin /usr/bin /bin; do
  if [ -x "$_d/pf" ]; then
    _pf_bin="$_d/pf"
    break
  fi
done
if [ -z "$_pf_bin" ]; then
  echo 'pf binary not found in system PATH (/usr/local/bin, /usr/bin, /bin)' >&2
  exit 1
fi

for _pf_d in TrustedUserCAKeys AuthorizedPrincipalsCommand; do
  if grep -rqE "^${{_pf_d}}" /etc/ssh/sshd_config {sshd_drop_in_dir}/ 2>/dev/null; then
    echo "conflicting sshd directive '$_pf_d' found; remove before initializing pf" >&2
    exit 1
  fi
done

install -d -m 700 /var/lib/pf
openssl genpkey -algorithm ed25519 | systemd-creds encrypt --name=account - /var/lib/pf/account.cred

cat > /var/lib/pf/config.json << 'PFEOF'
{config_json}
PFEOF

systemd-run --pipe --wait --property=LoadCredentialEncrypted=account:/var/lib/pf/account.cred \\
  $_pf_bin -c /dev/null accept --invitation='{invitation}' --key='$CREDENTIALS_DIRECTORY/account'

ssh-keygen -A
systemd-run --pipe --wait --property=LoadCredentialEncrypted=account:/var/lib/pf/account.cred \\
  $_pf_bin openssh host-refresh --config=/var/lib/pf/config.json \\
  --host-keys-dir={host_keys_dir} --ca-pub-path={ca_pub_path} --no-sshd-reload

install -d -m 755 {sshd_drop_in_dir}

cat > {sshd_config_drop_in} << PFEOF
TrustedUserCAKeys {ca_pub_path}
$(for cert in {host_keys_dir}/ssh_host_*_key.cert; do [ -f "$cert" ] && echo "HostCertificate $cert"; done)
AuthorizedPrincipalsCommand $_pf_bin openssh auth-principals \\
  --host-certificate={host_keys_dir}/ssh_host_ed25519_key.cert \\
  --username=%u \\
  --certificate=%k
AuthorizedPrincipalsCommandUser {auth_user}
PubkeyAuthentication yes
PFEOF

cat > /etc/systemd/system/pf-host-refresh.service << PFEOF
[Unit]
Description=Provably Fine SSH host certificate refresh

[Service]
Type=oneshot
ExecStart=$_pf_bin openssh host-refresh --config=/var/lib/pf/config.json \\
  --host-keys-dir={host_keys_dir} --ca-pub-path={ca_pub_path}
LoadCredentialEncrypted=account:/var/lib/pf/account.cred
PFEOF

cat > /etc/systemd/system/pf-host-refresh.timer << 'PFEOF'
[Unit]
Description=Provably Fine SSH host certificate refresh timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
PFEOF

systemctl daemon-reload
systemctl enable --now pf-host-refresh.timer
if systemctl is-active sshd; then
  systemctl reload sshd
else
  systemctl enable --now sshd
fi

_ssh_port=$(sshd -T 2>/dev/null | awk '/^port /{{print $2}}')
_ssh_port=${{_ssh_port:-22}}

cat > /etc/systemd/system/pf-host-bastion.service << PFEOF
[Unit]
Description=Provably Fine bastion registration
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
LoadCredentialEncrypted=account:/var/lib/pf/account.cred
ExecStart=$_pf_bin --config /var/lib/pf/config.json bastion register --port $_ssh_port
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
PFEOF

systemctl daemon-reload
systemctl enable --now pf-host-bastion.service

if [ -d /etc/NetworkManager/dispatcher.d ]; then
  cat > /etc/NetworkManager/dispatcher.d/pf-host-refresh << 'PFEOF'
#!/bin/sh
case "$2" in
  up|connectivity-change)
    systemctl start pf-host-refresh.service
    ;;
esac
PFEOF
  chmod 755 /etc/NetworkManager/dispatcher.d/pf-host-refresh
fi
""")


def host_init_daemon_function(args: argparse.Namespace) -> None:
    """Print a shell script to stdout that sets up pf on this host."""

    invitation = common.parse_invitation(args.invitation)

    _print_init_script(
        args.invitation,
        invitation.directory_url,
        args.host_keys_dir,
        args.ca_pub_path,
        args.sshd_config_drop_in,
        args.auth_user,
    )


def host_uninit_function(args: argparse.Namespace) -> None:
    """Print a shell script to stdout that undoes host-init."""
    lines = [
        "#!/bin/sh",
        "set -eu",
        "",
        "systemctl disable --now pf-host-refresh.timer || true",
        "systemctl stop pf-host-refresh.service 2>/dev/null || true",
        "rm -f /etc/systemd/system/pf-host-refresh.service",
        "rm -f /etc/systemd/system/pf-host-refresh.timer",
        "systemctl disable --now pf-host-bastion.service || true",
        "rm -f /etc/systemd/system/pf-host-bastion.service",
        "rm -f /etc/NetworkManager/dispatcher.d/pf-host-refresh",
        "systemctl daemon-reload",
        "",
        f"rm -f {args.sshd_config_drop_in}",
        f"rm -f {args.ca_pub_path}",
        f"rm -f {args.host_keys_dir}/ssh_host_*_key.cert",
        "rm -rf /var/lib/pf",
        "",
        "if systemctl is-active sshd; then",
        "  systemctl reload sshd",
        "fi",
    ]
    sys.stdout.write("\n".join(lines) + "\n")


def host_refresh_function(args: argparse.Namespace) -> None:
    """Refresh host SSH certificates and CA public key."""
    c = client.configuration.Config.load(args.config)
    factory = client.Factory(c)
    login.ensure_session(c, factory)
    _do_refresh(c, args.host_keys_dir, args.ca_pub_path)
    if not args.no_sshd_reload:
        subprocess.run(["/usr/bin/systemctl", "reload", "sshd"], check=True, capture_output=True)
