import argparse
import sys
import traceback

import requests

from . import exceptions
from . import admin_ctl
from . import ssh_ctl

def _register_function(args):
    pass


def _login_function(args):
    pass


def _ping_function(args):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', default='http://127.0.0.1:8000/admin/directory', help='Directory to connect to')
    parser.add_argument('--root-key-id', help='Key id of the public key of the root certificate.')
    parser.add_argument('--ignore-ssh-agent', action='store_true', help='Read and write keys from/to disk, regardless of whether or not there is an SSH agent')
    subparsers = parser.add_subparsers()

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
    admin_ctl.add_subparsers(admin_parser)

    ssh_parser = subparsers.add_parser('ssh', help='SSH-related functions')
    ssh_ctl.add_subparsers(ssh_parser)

    args = parser.parse_args()

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
