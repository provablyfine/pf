import argparse
import sys
import traceback
import os
import os.path
import logging

import requests
import requests.auth

from .. import jwk
from .. import ssh
from . import config
from . import client
from . import exceptions
from . import ssh_utils
from . import admin_cli
from . import openssh_cli


logger = logging.getLogger(__name__)

def _config_function(args):
    response = requests.get(args.directory)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to read directory: {response.text}')
    c = config.Config(
        directory_url=args.directory,
    )
    c.save(args.config)


def _accept_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.invitation_auth(account=args.key, invitation=args.invitation)
    response = auth.post(url=auth.directory.accept_invitation, json={
        'account_public_key': auth.public_key
    })
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to accept invitation successfully: {response.text}')
    c.account_key = args.key
    c.save(args.config)


@ssh_utils.exception
def _login_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    if args.session_key is None:
        try:
            ssh_agent = ssh.agent.Client()
        except:
            raise exceptions.UI("Unable to connect to user's SSH agent")
        session_key = jwk.Private.generate_ed25519()
        ssh_agent.add(session_key, comment='pf-session', lifetime=1800)
        c.session_key = session_key.public().ssh_fingerprint()
    else:
        with open(args.session_key, 'rb') as f:
            data = f.read()
        try:
            session_key = ssh_utils.load_private_key(data)
        except ValueError:
            raise exceptions.UI('Unable to parse data either as PEM or SSH format')
        c.session_key = args.session_key

    auth = api.login_auth(account=c.account_key, session=c.session_key)
    response = auth.post(url=auth.directory.login, json={
        'session_public_key': session_key.public().to_dict()
    })
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to login successfully: {response.text}')
    c.save(args.config)


def _do_main(args):
    if args.debug > 0:
        match args.debug:
            case 3:
                level = logging.DEBUG
            case 2:
                level = logging.INFO
            case 1:
                level = logging.WARN
            case _:
                assert args.debug > 3
                level = logging.DEBUG

        logging.basicConfig(stream=sys.stdout, level=level)


    try:
        args.func(args)
        exitcode = 0
    except exceptions.UI as e:
        sys.stderr.write(f'{str(e)}\n')
        exitcode = 2
    except:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)


def pfa():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Increase debugging level', action='count', default=0)
    parser.add_argument('-c', '--config', help='configuration file', default=os.path.abspath(os.path.join(os.getcwd(), 'config.json')))
    admin_cli.add_subparsers(parser)

    args = parser.parse_args()

    _do_main(args)


def pf():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Increase debugging level', action='count', default=0)
    parser.add_argument('-c', '--config', help='configuration file', default=os.path.abspath(os.path.join(os.getcwd(), 'config.json')))
    subparsers = parser.add_subparsers(required=True)

    config_parser = subparsers.add_parser('config', help='Create a configuration file')
    config_parser.add_argument('--directory', default=os.getenv('PF_DIRECTORY_URL', 'https://pf.provablyfine.net/pf/directory'), help='Directory to connect to')
    config_parser.set_defaults(func=_config_function)

    register_parser = subparsers.add_parser('accept', help='Accept an invitation')
    register_parser.add_argument('--key', help='Private key to register', required=True)
    register_parser.add_argument('--invitation', help='Invitation you were given', required=True)
    register_parser.set_defaults(func=_accept_function)

    login_parser = subparsers.add_parser('login', help='Login')
    login_parser.add_argument('--session-key', default=None, help="Session key to associate with account. If none is provided, a new one is generated, stored in the user' SSH agent and its hash is saved in the configuration file")
    login_parser.set_defaults(func=_login_function)

    openssh_parser = subparsers.add_parser('openssh', help='OpenSSH integration')
    openssh_cli.add_subparsers(openssh_parser)

    args = parser.parse_args()

    _do_main(args)
