import argparse
import sys
import traceback
import os
import os.path
import logging

import requests

from . import exceptions
from . import admin
from . import ssh
from . import config


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


def _register_function(args):
    pass


def _login_function(args):
    pass


def _ping_function(args):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help='Increase debugging level', action='count', default=0)
    parser.add_argument('-c', '--config', help='configuration file', default=os.path.abspath(os.path.join(os.getcwd(), 'config.json')))
    subparsers = parser.add_subparsers()

    config_parser = subparsers.add_parser('config', help='Create a configuration file')
    parser.add_argument('--directory', default='http://127.0.0.1:8000/admin/directory', help='Directory to connect to')
    parser.add_argument('--root-key-id', help='Key id of the public key of the root certificate.', default=None)
    parser.add_argument('--ignore-ssh-agent', action='store_true', help='Read and write keys from/to disk, regardless of whether or not there is an SSH agent')
    config_parser.set_defaults(func=_config_function)

    register_parser = subparsers.add_parser('register', help='Register only once per account key.')
    register_parser.add_argument('--key', help='Private key to register', default='account.key')
    register_parser.add_argument('--bind-with', help='Secret to bind this key with')
    register_parser.set_defaults(func=_register_function)

    login_parser = subparsers.add_parser('login', help='Login')
    login_parser.add_argument('--key', help='Key to login with', default='account.key')
    login_parser.add_argument('-o', '--output', help='Temporary key to associate with account', default='tmp.key')
    login_parser.set_defaults(func=_login_function)

    ping_parser = subparsers.add_parser('ping', help='Ping admin')
    ping_parser.add_argument('--tmp-key', help='key to use to sign requests to the remote', default='tmp.key')
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
