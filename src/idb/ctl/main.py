import argparse
import sys
import traceback
import os
import os.path
import logging
import secrets

import requests
import requests.auth

from .. import jwk
from . import exceptions
from . import admin
from . import ssh
from . import config
from . import client
from . import ssh_agent


logger = logging.getLogger(__name__)

def _config_function(args):
    response = requests.get(args.directory)
    response.raise_for_status()
    c = config.Config(
        directory_url=args.directory,
        root_key_id=args.root_key_id,
        ignore_ssh_agent=args.ignore_ssh_agent,
        directory=response.json()
    )
    c.save(args.config)


def _accept_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    nonce = secrets.token_hex(16)
    auth = idb.invitation_auth(account=args.key, invitation=args.invitation)
    response = auth.post(url=c.directory['accept-invitation'], json={
        'account_public_key': auth.public_key,
        'nonce': nonce,
    })
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to accept invitation successfully: {response.text}')
    c.account_key = args.key
    c.save(args.config)


def _login_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    if args.session_key is None:
        try:
            ssh = ssh_agent.Client()
        except:
            raise exceptions.UI("Unable to connect to user' SSH agent")
        session_key = jwk.Private.generate_ed25519()
        ssh.add_key(session_key.to_ssh_bytes())
    else:
        with open(args.session_key, 'rb') as f:
            data = f.read()
        session_key = jwk.Private.from_pem(data)
    c.session_key = session_key.public().ssh_fingerprint()
    idb.login_auth(account=c.account_key, session=c.session_key)
    c.save(args.config)


def _ping_function(args):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Increase debugging level', action='count', default=0)
    parser.add_argument('-c', '--config', help='configuration file', default=os.path.abspath(os.path.join(os.getcwd(), 'config.json')))
    subparsers = parser.add_subparsers(required=True)

    config_parser = subparsers.add_parser('config', help='Create a configuration file')
    parser.add_argument('--directory', default='http://127.0.0.1:8000/idb/directory', help='Directory to connect to')
    parser.add_argument('--root-key-id', help='Key id of the public key of the root certificate.', default=None)
    parser.add_argument('--ignore-ssh-agent', action='store_true', help='Read and write keys from/to disk, regardless of whether or not there is an SSH agent')
    config_parser.set_defaults(func=_config_function)

    register_parser = subparsers.add_parser('accept', help='Accept an invitation')
    register_parser.add_argument('--key', help='Private key to register', default='account.key')
    register_parser.add_argument('--invitation', help='Invitation you were given')
    register_parser.set_defaults(func=_accept_function)

    login_parser = subparsers.add_parser('login', help='Login')
    login_parser.add_argument('--session-key', default=None, help="Session key to associate with account. If none is provided, a new one is generated, stored in the user' SSH agent and its hash is saved in the configuration file")
    login_parser.set_defaults(func=_login_function)

    ping_parser = subparsers.add_parser('ping', help='Ping IDB')
    ping_parser.add_argument('--session-key', help='key to use to sign requests to the remote', default='session.key')
    ping_parser.set_defaults(func=_ping_function)

    admin_parser = subparsers.add_parser('admin', help='Admin-related functions')
    admin.add_subparsers(admin_parser)

    ssh_parser = subparsers.add_parser('ssh', help='SSH-related functions')
    ssh.add_subparsers(ssh_parser)

    args = parser.parse_args()

    if args.debug > 0:
        match args.debug:
            case 3:
                level = logging.DEBUG
            case 2:
                level = logging.INFO
            case 1:
                level = logging.WARN
        logging.basicConfig(stream=sys.stdout, level=level)


    try:
        args.func(args)
        exitcode = 0
    except exceptions.UI as e:
        print(e)
        exitcode = 2
    except:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)
