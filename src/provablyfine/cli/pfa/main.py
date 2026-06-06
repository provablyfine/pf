import argparse
import signal
import sys

from ... import client, jwk, ssh
from .. import common
from . import audit_log_cli, auth_cli, bastion_cli, boundary_cli, grant_cli, identity_cli, role_cli, tag_cli, tenant_cli


def _initialize_function(args: argparse.Namespace) -> None:
    c = client.Config(directory_url=args.url)
    sc = client.Factory(c, timeout=args.timeout)
    if args.transient_key:
        # This is a convenient way to generate transient keys that never touch
        # the disk. i.e., ssh-keygen + ssh-add make this more difficult than
        # it should be
        key = jwk.Private.generate_ed25519()
        account_key_id = key.public().ssh_fingerprint()
        ssh_agent = ssh.agent.Client()
        ssh_agent.add(key, comment="pf-account", lifetime=60)
    elif args.key is None:
        _, account_key_id = common.generate_and_save_key()
    else:
        account_key_id = args.key
    sc.invitation(sc.public().initialize(), account_key_id).accept_invitation()
    c.account_key = account_key_id
    c.auth_name = "default"
    c.save(args.config)


def pfa() -> None:
    if sys.platform != "win32":
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser()
    common.add_common_args(parser)
    subparsers = parser.add_subparsers(required=True, dest="command", metavar="command")

    version_parser = subparsers.add_parser("version", help="Print current version number")
    version_parser.set_defaults(func=common.version_function)

    accept_parser = subparsers.add_parser("accept", help="Accept an invitation")
    common.setup_accept_subparser(accept_parser)

    login_parser = subparsers.add_parser("login", help="Login using the configured auth method")
    common.setup_login_subparser(login_parser)

    initialize_parser = subparsers.add_parser("initialize", help="Initialize a new server and register account key")
    initialize_parser.add_argument("url", help="Directory URL of the server")
    group = initialize_parser.add_mutually_exclusive_group()
    group.add_argument("--key", default=None, help="Account key (filename or fingerprint)")
    group.add_argument(
        "--transient-key", action="store_true", help="Generate an account key and store it in ssh-agent for 60s"
    )
    initialize_parser.set_defaults(func=_initialize_function)

    boundary_parser = subparsers.add_parser("boundary", help="View and edit boundaries")
    boundary_cli.add_subparser(boundary_parser)

    tag_parser = subparsers.add_parser("tag", help="View and edit tags")
    tag_cli.add_subparser(tag_parser)

    role_parser = subparsers.add_parser("role", help="View and edit roles")
    role_cli.add_subparser(role_parser)

    identity_parser = subparsers.add_parser("identity", help="View and edit identities")
    identity_cli.add_subparser(identity_parser)

    grant_parser = subparsers.add_parser("grant", help="Generate grants")
    grant_cli.add_subparser(grant_parser)

    tenant_parser = subparsers.add_parser("tenant", help="View and manage tenants")
    tenant_cli.add_subparser(tenant_parser)

    auth_parser = subparsers.add_parser("auth", help="Manage authentication configurations")
    auth_cli.add_subparser(auth_parser)

    bastion_parser = subparsers.add_parser("bastion", help="View and edit bastions")
    bastion_cli.add_subparser(bastion_parser)

    audit_log_parser = subparsers.add_parser("audit-log", help="View audit log")
    audit_log_cli.add_subparser(audit_log_parser)

    args = parser.parse_args()

    common.do_main("pfa", args)
