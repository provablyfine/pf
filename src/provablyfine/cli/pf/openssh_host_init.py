import argparse
import base64
import os

from ... import client, jwk, ssh
from .. import common, login
from . import host


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
        cert_path = pubkey_path.removesuffix(".pub") + ".cert"
        client.configuration.write_file_atomic(cert_path, openssh_cert + b"\n", mode="wb")


def _do_refresh(c: client.Config, host_keys_dir: str, ca_pub_path: str) -> None:
    assert c.session_key_pem is not None
    session_key = client.ssh_utils.load_private_key(c.session_key_pem.encode())
    factory = client.Factory(c)
    http = client.http_client.Client(c)
    _sign_host_certificates_with_auth(http.session_auth_with_key(session_key), host_keys_dir)
    ca_pubkey = factory.public().get_user_trusted_keys_public()
    client.configuration.write_file_atomic(ca_pub_path, ca_pubkey, mode="w")


def _settings(args: argparse.Namespace, invitation: str, directory_url: str) -> host.base.Settings:
    return host.base.Settings(
        invitation=invitation,
        directory_url=directory_url,
        host_keys_dir=args.host_keys_dir,
        ca_pub_path=args.ca_pub_path,
        sshd_config_drop_in=args.sshd_config_drop_in,
        auth_user=args.auth_user,
        pf_binary=args.pf_binary,
        sshd_config=args.sshd_config,
        sshd_service=args.sshd_service,
    )


def host_init_daemon_function(args: argparse.Namespace) -> None:
    """Set up pf on this host. Must run as root unless --dry-run is given."""
    provider = host.provider()
    invitation = common.parse_invitation(args.invitation)
    settings = _settings(args, args.invitation, invitation.directory_url)
    host.apply(args.dry_run, lambda o: provider.init(o, settings))


def host_uninit_function(args: argparse.Namespace) -> None:
    """Undo host-init. Must run as root unless --dry-run is given."""
    provider = host.provider()
    settings = host.base.Settings(
        invitation="",
        directory_url="",
        host_keys_dir=args.host_keys_dir,
        ca_pub_path=args.ca_pub_path,
        sshd_config_drop_in=args.sshd_config_drop_in,
        auth_user="",
        sshd_config=args.sshd_config,
        sshd_service=args.sshd_service,
    )
    host.apply(args.dry_run, lambda o: provider.uninit(o, settings))


def host_refresh_function(args: argparse.Namespace) -> None:
    """Refresh host SSH certificates and CA public key."""
    c = client.configuration.Config.load(args.config)
    factory = client.Factory(c)
    login.ensure_session(c, factory)
    _do_refresh(c, args.host_keys_dir, args.ca_pub_path)
    if not args.no_sshd_reload:
        host.reload_sshd()
