import requests
import json
import tabulate

from . import config
from . import exceptions
from . import client

def _initialize_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    response = idb.no_auth.post(c.directory['initialize'])
    if response.status_code == 204:
        raise exceptions.UI(f'Unable to initialize app: it is already initialized.')
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to initialize app: expected error.')
    data = response.json()
    print(data["key"]['k'])


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.add_argument('--format', choices=['json', 'text'], default='text', help='Initialize idb server')
    initialize_parser.set_defaults(func=_initialize_function)

    #identity_create
