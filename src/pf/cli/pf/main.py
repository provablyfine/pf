import argparse
import logging
import os
import os.path
import sys
import traceback
import urllib.parse

import requests
import tabulate

from ... import client
from ... import log
from .. import login
from . import bastion_cli, openssh_cli, ssh_cli

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "pf", "config.json")


@client.ssh_utils.exception
def _hosts_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.get(f"{auth.directory.ssh}/hosts")
    if response.status_code != 200:
        raise client.exceptions.UI(response.json().get("title", "Failed to list hosts"))
    rows = []
    for entry in response.json().get("hosts", []):
        rows.append((entry["hostname"], entry["type"], entry.get("command", "")))
    if len(rows) > 0:
        output = tabulate.tabulate(rows, headers=("host", "type", "details"))
        print(output)


def _config_function(args):
    response = requests.get(args.directory)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to read directory: {response.text}")
    c = client.Config(
        directory_url=args.directory,
        directory=response.json(),
    )
    c.save(args.config)


def _parse_invitation(invitation: str) -> str:
    if invitation.startswith("http"):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(invitation).query)
        keys = params.get("invitation")
        if not keys:
            raise client.exceptions.UI("No invitation key found in URL")
        return keys[0]
    return invitation


def _accept_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    invitation_key = _parse_invitation(args.invitation)
    auth = api.invitation_auth(account=args.key, invitation=invitation_key)
    response = auth.post(url=auth.directory.accept_invitation, json={"account_public_key": auth.public_key})
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to accept invitation successfully: {response.text}")
    c.account_key = args.key
    c.save(args.config)


@client.ssh_utils.exception
def _login_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth_name = args.auth or "default"
    login.login(api, c, auth_name, args.config, session_key_path=args.session_key)


def _do_main(args):
    log.setup(args.debug, log.filename("pf", args))

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


def pf():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="configuration file", default=_DEFAULT_CONFIG)
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    subparsers = parser.add_subparsers(required=True, dest="_cmd1")

    config_parser = subparsers.add_parser("config", help="Create a configuration file")
    config_parser.add_argument(
        "--directory",
        default=os.getenv("PF_DIRECTORY_URL", "https://pf.provablyfine.net/pf/directory"),
        help="Directory to connect to. Default: %(default)s",
    )
    config_parser.set_defaults(func=_config_function)

    register_parser = subparsers.add_parser("accept", help="Accept an invitation")
    register_parser.add_argument("--key", help="Private key to register", required=True)
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

    bastion_cli.add_subparser(subparsers)

    ssh_cli.add_subparser(subparsers)

    hosts_parser = subparsers.add_parser("hosts", help="List accessible hosts and permissions")
    hosts_parser.set_defaults(func=_hosts_function)

    args = parser.parse_args()

    _do_main(args)
