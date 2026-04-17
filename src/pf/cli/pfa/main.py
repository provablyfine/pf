import argparse
import os
import os.path
import sys
import traceback
import urllib.parse

import requests

from ... import client, log
from .. import login
from . import auth_cli, bastion_cli, boundary_cli, grant_cli, identity_cli, role_cli, tag_cli, tenant_cli

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "pf", "config.json")


def _initialize_function(args: argparse.Namespace) -> None:
    response = requests.get(args.url, timeout=args.timeout)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read directory: {response.text}")
    c = client.Config(directory_url=args.url, directory=response.json())
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.initialize(args.key)
    c.account_key = args.key
    c.auth_name = "default"
    c.save(args.config)


def _connect_function(args: argparse.Namespace) -> None:
    parsed = urllib.parse.urlparse(args.url)
    params = urllib.parse.parse_qs(parsed.query)
    clean_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))

    invitation = params.get("invitation", [None])[0] or args.invitation
    auth_name = params.get("auth", [None])[0] or args.auth or "default"

    response = requests.get(clean_url, timeout=args.timeout)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read directory: {response.text}")
    c = client.Config(directory_url=clean_url, directory=response.json())
    sc = client.sync.Client(c, timeout=args.timeout)

    if invitation and args.key:
        sc.connect(invitation, args.key)
        c.account_key = args.key

    c.auth_name = auth_name
    c.save(args.config)


def _login_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    auth_name = args.auth or c.auth_name or "default"
    login.login(api, c, auth_name, args.config, session_key_path=args.session_key)


def _do_main(args: argparse.Namespace) -> None:
    log.setup(args.debug, log.filename("pfa", args))

    if getattr(args, "auto_login", False):
        try:
            c = client.Config.load(args.config)
            if not login.has_valid_session(c):
                api = client.Client(c, timeout=args.timeout)
                auth_name = c.auth_name or "default"
                login.login(api, c, auth_name, args.config)
        except client.exceptions.UI:
            pass

    try:
        args.func(args)
        exitcode = 0
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)


def pfa():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="configuration file", default=_DEFAULT_CONFIG)
    parser.add_argument("--auto-login", action="store_true", default=False)
    parser.add_argument("--timeout", default=1.0, help="Timeout for HTTP requests")
    parser.add_argument(
        "-d", "--debug", help="Increase debugging level", action="count", default=int(os.environ.get("PF_DEBUG") or "0")
    )
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    subparsers = parser.add_subparsers(required=True, dest="_cmd1")

    initialize_parser = subparsers.add_parser("initialize", help="Initialize a new server and register account key")
    initialize_parser.add_argument("url", help="Directory URL of the server")
    initialize_parser.add_argument("--key", required=True, help="Account key (filename or fingerprint)")
    initialize_parser.set_defaults(func=_initialize_function)

    connect_parser = subparsers.add_parser("connect", help="Connect to an existing server")
    connect_parser.add_argument("url", help="Directory URL (may include invitation= and auth= query params)")
    connect_parser.add_argument("--auth", default=None, help="Auth config name")
    connect_parser.add_argument("--invitation", default=None, help="Invitation key")
    connect_parser.add_argument("--key", default=None, help="Account key (filename or fingerprint)")
    connect_parser.set_defaults(func=_connect_function)

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

    args = parser.parse_args()

    _do_main(args)
