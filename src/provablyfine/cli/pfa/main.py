import argparse
import os
import os.path
import signal
import sys
import traceback

from ... import __version__, client, log
from .. import key_utils, login
from . import audit_log_cli, auth_cli, bastion_cli, boundary_cli, grant_cli, identity_cli, role_cli, tag_cli, tenant_cli

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "provablyfine", "config.json")


def _initialize_function(args: argparse.Namespace) -> None:
    c = client.Config(directory_url=args.url)
    sc = client.sync.Client(c, timeout=args.timeout)
    if args.key is None:
        _, account_key_id = key_utils.generate_and_save_key()
    else:
        account_key_id = args.key
    sc.initialize(account_key_id)
    c.account_key = account_key_id
    c.auth_name = "default"
    c.save(args.config)


def _login_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    auth_name = args.auth or c.auth_name or "default"
    c.session_key = login.login(c, sc, auth_name, session_key_path=args.session_key)
    c.save(args.config)


def _version_function(args: argparse.Namespace) -> None:
    print(__version__)


def _do_main(args: argparse.Namespace) -> None:
    log.setup(args.debug, log.filename("pfa", args))

    try:
        args.func(args)
        exitcode = 0
    except client.exceptions.KeyExpired:
        sys.stderr.write('Your session has expired. You must "pfa login".\n')
        exitcode = 2
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)


def pfa() -> None:
    if sys.platform != "win32":
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="configuration file. Default: %(default)s", default=_DEFAULT_CONFIG)
    parser.add_argument("--timeout", default=1.0, help="Timeout for HTTP requests. Default: %(default)s")
    parser.add_argument("-d", "--debug", help="Debug level", action="count", default=0)
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    subparsers = parser.add_subparsers(required=True, dest="command", metavar="command")

    version_parser = subparsers.add_parser("version", help="Print current version number")
    version_parser.set_defaults(func=_version_function)

    initialize_parser = subparsers.add_parser("initialize", help="Initialize a new server and register account key")
    initialize_parser.add_argument("url", help="Directory URL of the server")
    initialize_parser.add_argument("--key", default=None, help="Account key (filename or fingerprint)")
    initialize_parser.set_defaults(func=_initialize_function)

    login_parser = subparsers.add_parser("login", help="Login using the configured auth method")
    login_parser.add_argument("--auth", default=None, help="Auth config name to use for login")
    login_parser.add_argument(
        "--session-key",
        default=None,
        help="Session key file. If none is provided, a new one is generated in SSH agent.",
    )
    login_parser.set_defaults(func=_login_function)

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

    _do_main(args)
