import argparse
import base64
import logging
import os

import provablyfine_client as pfc

from ... import client, jwk, ssh
from . import host, openssh_host_init, openssh_pam_session_deadline_linux, openssh_session_reaper

logger = logging.getLogger(__name__)


def _user_trusted_keys_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    print(client.Factory(c, timeout=args.timeout).public().get_user_trusted_keys_public())


def _sign_host_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()

    public_keys: list[dict[str, str]] = []
    filename_from_fingerprint: dict[str, str] = {}
    for filename in args.public_key:
        with open(filename, "rb") as f:
            key = f.read()
            public_key = jwk.Public.from_openssh(key)
            public_keys.append(public_key.to_dict())
            filename_from_fingerprint[public_key.ssh_fingerprint()] = filename

    cert_response = sc.sign_host_certificates(public_keys)
    for certificate in cert_response.certificates:
        openssh_certificate = base64.b64decode(certificate)
        cert = ssh.cert.Cert.from_openssh(openssh_certificate)
        public_key_filename = filename_from_fingerprint[cert.public_key.ssh_fingerprint()]
        cert_filename = f"{public_key_filename.rstrip('.pub')}.cert"
        fd = os.open(cert_filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with open(fd, "wb+") as f:
            f.write(openssh_certificate + b"\n")


def _register_session(directory: str, cert: ssh.cert.Cert) -> None:
    """Tell the session reaper about a connection, and about its deadline if it has one.

    A failure is logged and ignored. It must never stop a login.
    """
    deadline = cert.extensions.session_deadline
    connection_id = cert.extensions.connection_id
    if connection_id is None:
        return
    try:
        openssh_session_reaper.register_session(
            directory, deadline=deadline, connection_id=connection_id, table=host.procs.default_table()
        )
    except Exception:
        logger.warning("failed to register the session; failing open", exc_info=True)


def _authorized_principals(args: argparse.Namespace) -> None:
    with open(args.host_certificate, "rb") as f:
        data = f.read()
        host_certificate = ssh.cert.Cert.from_openssh(data)
        host_items = host_certificate.identifier.split(":")
        if len(host_items) == 0:
            raise pfc.exceptions.UI(f"Invalid host identifier={host_certificate.identifier}")
        host_identifier = host_items[0]

    certificate = base64.b64decode(args.certificate.encode("ascii"))
    cert = ssh.serde.deserialize_cert(certificate)
    accepted: list[str] = []
    for principal in cert.principals:
        items = principal.split("@")
        if len(items) != 2:
            raise pfc.exceptions.UI(f"Invalid user principal={principal}")
        username, host_id = items
        if username != args.username:
            # the certificate grants access to a username that is not the user that is currently
            # requested by the SSH connection
            continue
        if host_id != host_identifier:
            raise pfc.exceptions.UI(f"Invalid user host id={host_id} expected={host_identifier}")
        accepted.append(principal)
    if accepted and args.deadline_dir is not None:
        _register_session(args.deadline_dir, cert)
    print("\n".join(accepted))


def _add_windows_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--sshd-config",
        default=None,
        help="Windows only: the sshd_config file to edit. By default, the one in %%ProgramData%%\\ssh",
    )
    parser.add_argument("--sshd-service", default="sshd", help="Windows only: the name of the sshd service")


def add_subparsers(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    sign_host_parser = subparsers.add_parser("sign-host")
    sign_host_parser.add_argument("--public-key", action="append", default=[], help="Public key to sign")
    sign_host_parser.set_defaults(func=_sign_host_function)

    user_trusted_keys_parser = subparsers.add_parser("user-trusted-keys")
    user_trusted_keys_parser.set_defaults(func=_user_trusted_keys_function)

    authorized_principals_parser = subparsers.add_parser(
        "auth-principals", help="Command to use for AuthorizedPrincipalsCommand"
    )
    authorized_principals_parser.add_argument(
        "--host-certificate", help="One of the signed host certificates", default="/etc/sshd/ssh_host_ed25519_key.cert"
    )
    authorized_principals_parser.add_argument("--username", required=True)
    authorized_principals_parser.add_argument("--certificate", help="base64 user certificate to parse", required=True)
    authorized_principals_parser.add_argument(
        "--deadline-dir",
        default=None,
        help="Directory where to record connections that have a session deadline, for the session reaper",
    )
    authorized_principals_parser.set_defaults(func=_authorized_principals)

    host_init_parser = subparsers.add_parser(
        "host-init", help="Initialize configuration of local SSH daemon. Run as root."
    )
    host_init_parser.add_argument(
        "--dry-run", action="store_true", default=False, help="Print what would be done and change nothing"
    )
    host_init_parser.add_argument("--invitation", required=True, help="Invitation key")
    defaults = host.defaults()
    host_init_parser.add_argument(
        "--auth-user", default=defaults.auth_user, help="User for AuthorizedPrincipalsCommandUser"
    )
    host_init_parser.add_argument(
        "--sshd-config-drop-in", default=defaults.sshd_config_drop_in, help="Path to sshd_config.d drop-in file"
    )
    host_init_parser.add_argument(
        "--host-keys-dir", default=defaults.host_keys_dir, help="Directory containing host SSH keys"
    )
    host_init_parser.add_argument("--ca-pub-path", default=defaults.ca_pub_path, help="Path to CA public key file")
    _add_windows_options(host_init_parser)
    host_init_parser.add_argument(
        "--pf-binary",
        default=None,
        help="The pf binary that sshd and the services run. By default, the installed pf",
    )
    host_init_parser.set_defaults(func=openssh_host_init.host_init_daemon_function)

    host_uninit_parser = subparsers.add_parser("host-uninit", help="Undo host-init. Run as root.")
    host_uninit_parser.add_argument(
        "--dry-run", action="store_true", default=False, help="Print what would be done and change nothing"
    )
    host_uninit_parser.add_argument(
        "--sshd-config-drop-in", default=defaults.sshd_config_drop_in, help="Path to sshd_config.d drop-in file"
    )
    host_uninit_parser.add_argument(
        "--host-keys-dir", default=defaults.host_keys_dir, help="Directory containing host SSH keys"
    )
    host_uninit_parser.add_argument("--ca-pub-path", default=defaults.ca_pub_path, help="Path to CA public key file")
    _add_windows_options(host_uninit_parser)
    host_uninit_parser.set_defaults(func=openssh_host_init.host_uninit_function)

    session_reaper_parser = subparsers.add_parser(
        "session-reaper",
        help="End SSH sessions when their certificate deadline passes. Run as root. For hosts without PAM hooks.",
    )
    session_reaper_parser.add_argument(
        "--deadline-dir", default=None, help="Directory where auth-principals records connections"
    )
    session_reaper_parser.add_argument(
        "--sessions-dir",
        default=None,
        help="Linux: directory where the PAM hook records open sessions. The reaper then only ends sessions on request",
    )
    session_reaper_parser.add_argument(
        "--kill-dir", default=None, help="Directory where kill requests are written. Only root may write there"
    )
    session_reaper_parser.add_argument(
        "--live-dir",
        default=None,
        help="Directory where session start and end events are written. Only root may write there",
    )
    session_reaper_parser.add_argument(
        "--interval", type=float, default=1.0, help="Seconds between checks of the records"
    )
    session_reaper_parser.add_argument(
        "--grace", type=float, default=5.0, help="Seconds a session has to end before it is killed"
    )
    session_reaper_parser.set_defaults(func=openssh_session_reaper.session_reaper_function)

    session_deadline_parser = subparsers.add_parser(
        "pam-session-deadline",
        help="Linux only: PAM session hook enforcing a certificate's session TTL. For use with pam_exec.",
    )
    session_deadline_parser.add_argument(
        "--ca-pub-path", default="/etc/ssh/pf_ca.pub", help="Path to CA public key file"
    )
    session_deadline_parser.add_argument(
        "--live-events-dir", default=None, help="Directory where session start and end events are written"
    )
    session_deadline_parser.add_argument(
        "--sessions-dir",
        default=None,
        help="Directory where each open session is recorded, so that the session reaper can end it",
    )
    session_deadline_parser.set_defaults(func=openssh_pam_session_deadline_linux.session_deadline_function)

    host_refresh_parser = subparsers.add_parser("host-refresh", help="Refresh configuration of local SSH daemon")
    host_refresh_parser.add_argument("--config", required=True, help="Path to pf config.json")
    host_refresh_parser.add_argument("--host-keys-dir", required=True, help="Directory containing host SSH keys")
    host_refresh_parser.add_argument("--ca-pub-path", required=True, help="Path to CA public key file")
    host_refresh_parser.add_argument("--no-sshd-reload", action="store_true", default=False)
    host_refresh_parser.set_defaults(func=openssh_host_init.host_refresh_function)
