import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile

from ... import client, jwk, ssh


def _preflight_check(sshd_config_dir: str, sshd_config_file: str) -> None:
    """Raise RuntimeError if conflicting sshd directives are found."""
    conflicts: list[str] = []
    conflicting_directives = ["TrustedUserCAKeys", "AuthorizedPrincipalsCommand"]

    for config_path in [sshd_config_dir, sshd_config_file]:
        if not os.path.exists(config_path):
            continue
        if os.path.isdir(config_path):
            for filename in os.listdir(config_path):
                filepath = os.path.join(config_path, filename)
                if os.path.isfile(filepath):
                    conflicts += _check_file_for_directives(filepath, conflicting_directives)
        else:
            conflicts += _check_file_for_directives(config_path, conflicting_directives)

    if conflicts:
        raise RuntimeError(
            "Conflicting sshd directives found; remove them before initializing pf:\n"
            + "\n".join(f"  {c}" for c in conflicts)
        )


def _check_file_for_directives(filepath: str, directives: list[str]) -> list[str]:
    conflicts: list[str] = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                for directive in directives:
                    if line.startswith(directive):
                        conflicts.append(f"'{directive}' in {filepath}")
    except Exception:
        pass
    return conflicts


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


def _write_sshd_drop_in(drop_in_path: str, host_keys_dir: str, ca_pub_path: str, auth_user: str) -> None:
    drop_in_content = [f"TrustedUserCAKeys {ca_pub_path}"]
    for key_type in ["ed25519", "ecdsa", "rsa"]:
        cert_path = os.path.join(host_keys_dir, f"ssh_host_{key_type}_key.cert")
        if os.path.exists(cert_path):
            drop_in_content.append(f"HostCertificate {cert_path}")

    drop_in_content += [
        f"AuthorizedPrincipalsCommand /usr/bin/pf openssh authorized-principals"
        f" --host-certificate={os.path.join(host_keys_dir, 'ssh_host_ed25519_key.cert')}"
        f" --username=%u --certificate=%k",
        f"AuthorizedPrincipalsCommandUser {auth_user}",
        "PubkeyAuthentication yes",
    ]

    _write_file_atomic(drop_in_path, "".join(f"{line}\n" for line in drop_in_content), mode="w")


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
    sc = client.sync.Client(config)

    sc.login_http_sig_with_keys(account_key, session_key)

    http = client.http_client.Client(config)
    _sign_host_certificates_with_auth(http.session_auth_with_key(session_key), host_keys_dir)

    ca_pubkey = sc.get_user_trusted_keys_public()
    _write_file_atomic(ca_pub_path, ca_pubkey, mode="w")


def _read_json_from_socket(sock: socket.socket) -> dict[str, str]:
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            pass
    return json.loads(data.decode("utf-8"))


def _write_json_to_socket(sock: socket.socket, response: dict[str, str]) -> None:
    sock.sendall(json.dumps(response).encode("utf-8"))


def _handle_initialization(args: argparse.Namespace, request_data: dict[str, str]) -> None:
    invitation = request_data.get("invitation")
    tenant_url = request_data.get("tenant_url")
    auth_user = request_data.get("auth_user", "nobody")

    if not invitation:
        raise RuntimeError("Missing 'invitation' field")

    directory_url = tenant_url or "https://pf.provablyfine.net/pf/directory"

    _preflight_check(os.path.dirname(args.sshd_config_drop_in), "/etc/ssh/sshd_config")

    account_key = jwk.Private.generate_ed25519()

    temp_config = client.configuration.Config(directory_url=directory_url)
    http = client.http_client.Client(temp_config)
    auth = http.invitation_auth_with_key(account_key, invitation)
    response = auth.post(
        url=auth.directory.accept_invitation,
        json={"account_public_key": auth.account_public_key.to_dict()},
    )
    if response.status_code != 204:
        raise RuntimeError(f"Failed to accept invitation: {response.text}")

    subprocess.run(
        ["/usr/bin/systemd-creds", "encrypt", "-", "/var/lib/pf/account.cred"],
        input=account_key.to_openssh(),
        check=True,
        capture_output=True,
    )

    _write_file_atomic(
        "/var/lib/pf/config.json",
        json.dumps({"directory_url": directory_url, "account_key": "$CREDENTIALS_DIRECTORY/account"}),
        mode="w",
    )

    subprocess.run(["/usr/bin/ssh-keygen", "-A"], check=True, capture_output=True)

    _do_refresh(account_key, directory_url, args.host_keys_dir, args.ca_pub_path)

    _write_sshd_drop_in(args.sshd_config_drop_in, args.host_keys_dir, args.ca_pub_path, auth_user)

    subprocess.run(["/usr/bin/systemctl", "reload", "sshd"], check=True, capture_output=True)


def host_init_daemon_function(args: argparse.Namespace) -> None:
    """Socket-activated init daemon. Reads JSON from systemd socket fd 3."""

    try:
        listening_sock = socket.socket(fileno=3)
    except Exception as e:
        sys.stderr.write(f"Failed to open socket fd 3: {e}\n")
        sys.exit(1)

    while True:
        conn, _ = listening_sock.accept()

        try:
            request_data = _read_json_from_socket(conn)
        except Exception as e:
            _write_json_to_socket(conn, {"status": "error", "message": f"Invalid JSON: {e}"})
            conn.close()
            continue

        try:
            _handle_initialization(args, request_data)
        except Exception as e:
            _write_json_to_socket(conn, {"status": "error", "message": str(e)})
            conn.close()
            continue

        _write_json_to_socket(conn, {"status": "ok"})
        conn.close()
        break


def host_refresh_function(args: argparse.Namespace) -> None:
    """Refresh host SSH certificates and CA public key."""

    c = client.configuration.Config.load(args.config)

    if c.account_key and "$" in c.account_key:
        c.account_key = os.path.expandvars(c.account_key)

    with open(c.account_key or "", "rb") as f:
        account_key = client.ssh_utils.load_private_key(f.read())

    _do_refresh(account_key, c.directory_url, args.host_keys_dir, args.ca_pub_path)

    subprocess.run(["/usr/bin/systemctl", "reload", "sshd"], check=True, capture_output=True)
