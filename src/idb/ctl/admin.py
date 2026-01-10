import json

import requests
import tabulate

from . import config
from . import exceptions
from . import client
from . import permission


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
    response = auth.get(c.directory['boundary'])
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to get list of boundaries')
    data = response.json()
    match args.format:
        case 'json':
            output = json.dumps(data['boundaries'], indent=2)
        case 'text':
            rows = []
            for boundary in data['boundaries']:
                rows.append([boundary['id'], boundary['name']])
            output = tabulate.tabulate(rows, headers=['id', 'name'])
    print(output)


def _boundary_read_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.get(f'{c.directory["boundary"]}/{args.id}')
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to get boundary')
    data = response.json()
    match args.format:
        case 'json':
            output = json.dumps(data, indent=2)
        case 'text':
            rows = []
            rows.append(('id', data['id']))
            rows.append(('name', data['name']))
            rows.append(('description', data['description']))
            for denies in data['denies']:
                rows.append(('denies', permission.dict_to_string(denies)))
            output = tabulate.tabulate(rows, tablefmt='plain')
    print(output)


def _add_boundary_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list')
    list_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    list_parser.set_defaults(func=_boundary_list_function)

    read_parser = subparsers.add_parser('read', help='Show details on a specific boundary')
    read_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    read_parser.add_argument('id', type=int, help='Boundary id')
    read_parser.set_defaults(func=_boundary_read_function)


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.set_defaults(func=_initialize_function)

    boundary_parser = subparsers.add_parser('boundary')
    _add_boundary_subparser(boundary_parser)
