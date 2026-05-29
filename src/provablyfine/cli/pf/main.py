import argparse
import dataclasses
import logging
import signal
import sys
import urllib.parse

import tabulate

from ... import client
from .. import common
from . import bastion_cli, openssh_cli, ssh_cli

logger = logging.getLogger(__name__)


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
        _, account_key_id = common.generate_and_save_key()
    else:
        account_key_id = args.key
    c = client.Config(
        directory_url=invitation.directory_url,
        auth_name=invitation.auth_name,
    )
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.connect(invitation.key, account_key_id)
    c.account_key = account_key_id
    c.save(args.config)


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


def pf() -> None:
    if sys.platform != "win32":
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    parser = argparse.ArgumentParser()
    common.add_common_args(parser)
    subparsers = parser.add_subparsers(required=True, dest="command", metavar="command")

    version_parser = subparsers.add_parser("version", help="Print current version number")
    version_parser.set_defaults(func=common.version_function)

    register_parser = subparsers.add_parser("accept", help="Accept an invitation")
    register_parser.add_argument("--key", help="Private key to register", default=None)
    register_parser.add_argument("--invitation", help="Invitation you were given", required=True)
    register_parser.set_defaults(func=_accept_function)

    login_parser = subparsers.add_parser("login", help="Login")
    common.setup_login_subparser(login_parser)

    openssh_parser = subparsers.add_parser("openssh", help="OpenSSH integration")
    openssh_cli.add_subparsers(openssh_parser)

    bastion_parser = subparsers.add_parser("bastion", help="Bastion management")
    bastion_cli.add_subparser(bastion_parser)

    ssh_parser = subparsers.add_parser("ssh", help="Login, get certificate, and connect via SSH")
    ssh_cli.add_subparser(ssh_parser)

    hosts_parser = subparsers.add_parser("hosts", help="List accessible hosts and permissions")
    hosts_parser.set_defaults(func=_hosts_function)

    args = parser.parse_args()

    common.do_main("pf", args)
