import argparse
import logging
import os
import os.path
import signal
import sys
import traceback
import urllib.parse
import dataclasses

import requests
import tabulate

from ... import __version__, client, log
from .. import key_utils, login
from . import bastion_cli, openssh_cli, ssh_cli

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "provablyfine", "config.json")


@client.ssh_utils.exception
def _hosts_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    data = sc.list_ssh_hosts()
    rows: list[tuple[str, str, str, str]] = []
    for entry in data.hosts:
        username_list = entry.username_list or ["*"]
        command_list = entry.command_list or []
        details = ", ".join(command_list)
        for username in username_list:
            rows.append((entry.hostname, entry.type, username, details))
    if len(rows) > 0:
        output = tabulate.tabulate(rows, headers=("host", "type", "username", "details"))
        print(output)


def _config_function(args: argparse.Namespace) -> None:
    try:
        response = requests.get(args.directory, timeout=0.5)
    except requests.exceptions.ConnectionError:
        raise client.exceptions.UI(f"Unable to connect to {args.directory}")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read directory: {response.text}")
    c = client.Config(
        directory_url=args.directory,
        directory=response.json(),
    )
    c.save(args.config)


@dataclasses.dataclass
class Invitation:
    directory_url: str
    key: str
    auth_name: str


def _parse_invitation(invitation_url: str) -> Invitation:
    url = urllib.parse.urlsplit(invitation_url)
    qs = urllib.parse.parse_qs(url.query)
    invitation = qs.get("invitation")
    if not invitation:
        raise client.exceptions.UI("No invitation key found in URL")
    auth = qs.get("auth")
    if not auth:
        raise client.exceptions.UI("No auth key found in URL")
    url_no_qs = url._replace(query="")
    directory_url = urllib.parse.urlunsplit(url_no_qs)
    return Invitation(directory_url=directory_url, key=invitation[0], auth_name=auth[0])


def _accept_function(args: argparse.Namespace) -> None:
    invitation = _parse_invitation(args.invitation)
    if args.key is None:
        _, account_key_id = key_utils.generate_and_save_key()
    else:
        account_key_id = args.key
    # XXX: remove 
    try:
        response = requests.get(invitation.directory_url, timeout=0.5)
    except requests.exceptions.ConnectionError:
        raise client.exceptions.UI(f"Unable to connect to {invitation.directory_url}")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read directory: {response.text}")
    c = client.Config(
        directory_url=invitation.directory_url,
        auth_name=invitation.auth_name,
        directory=response.json(),
    )
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.connect(invitation.key, account_key_id)
    c.account_key = account_key_id
    c.save(args.config)


@client.ssh_utils.exception
def _login_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    auth_name = args.auth or "default"
    c.session_key = login.login(c, sc, auth_name, session_key_path=args.session_key)
    c.save(args.config)


def _version_function(args: argparse.Namespace) -> None:
    print(__version__)


def _do_main(args: argparse.Namespace) -> None:
    log.setup(args.debug, log.filename("pf", args))

    try:
        args.func(args)
        exitcode = 0
    except client.exceptions.KeyExpired:
        sys.stderr.write('Your session has expired. You must "pf login".\n')
        exitcode = 2
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)


def pf() -> None:
    if sys.platform != "win32":
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="configuration file. Default: %(default)s", default=_DEFAULT_CONFIG)
    parser.add_argument("--timeout", default=1.0, help="Timeout for HTTP requests. Default: %(default)s")
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    subparsers = parser.add_subparsers(required=True, dest="command", metavar="command")

    version_parser = subparsers.add_parser("version", help="Print current version number")
    version_parser.set_defaults(func=_version_function)

    config_parser = subparsers.add_parser("config", help="Create a configuration file")
    config_parser.add_argument(
        "directory",
        help="Directory to connect to.",
    )
    config_parser.set_defaults(func=_config_function)

    register_parser = subparsers.add_parser("accept", help="Accept an invitation")
    register_parser.add_argument("--key", help="Private key to register", default=None)
    register_parser.add_argument("--invitation", help="Invitation you were given", required=True)
    register_parser.set_defaults(func=_accept_function)

    login_parser = subparsers.add_parser("login", help="Login")
    login_parser.add_argument(
        "--session-key",
        default=None,
        help="Session key to associate with account. "
        "If none is provided, a new one is generated, "
        "stored in the user' SSH agent and its hash is "
        "saved in the configuration file",
    )
    login_parser.add_argument(
        "--auth",
        default=None,
        help="Auth config name to use for login. Defaults to 'default'.",
    )
    login_parser.set_defaults(func=_login_function)

    openssh_parser = subparsers.add_parser("openssh", help="OpenSSH integration")
    openssh_cli.add_subparsers(openssh_parser)

    bastion_parser = subparsers.add_parser("bastion", help="Bastion management")
    bastion_cli.add_subparser(bastion_parser)

    ssh_parser = subparsers.add_parser("ssh", help="Login, get certificate, and connect via SSH")
    ssh_cli.add_subparser(ssh_parser)

    hosts_parser = subparsers.add_parser("hosts", help="List accessible hosts and permissions")
    hosts_parser.set_defaults(func=_hosts_function)

    args = parser.parse_args()

    _do_main(args)
