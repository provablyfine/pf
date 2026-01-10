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


def _boundary_list_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.post(c.directory['boundary-list'])
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to get list of boundaries')
    data = response.json()
    match args.format:
        case 'json':
            output = json.dumps(data)
        case 'text':
            rows = []
            for boundary in data['boundaries']:
                rows.append([boundary['id'], boundary['name']])
            output = tabulate.tabulate(rows, headers=['id', 'name'])
    print(output)


def _add_boundary_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list')
    list_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    list_parser.set_defaults(func=_boundary_list_function)


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.set_defaults(func=_initialize_function)

    boundary_parser = subparsers.add_parser('boundary')
    _add_boundary_subparser(boundary_parser)
