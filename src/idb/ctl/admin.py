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
    params = None
    if args.name is not None:
        params = {'name': args.name}
    response = auth.get(c.directory['boundary'], params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to get list of boundaries')
    data = response.json()
    match args.format:
        case 'json':
            output = json.dumps(data['boundaries'], indent=2)
        case 'text':
            rows = []
            for boundary in data['boundaries']:
                rows.append([boundary['id'], boundary['name'], boundary['description']])
            output = tabulate.tabulate(rows, headers=['id', 'name', 'description'])
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
            for denied in data['denied_list']:
                rows.append(('denied', permission.dict_to_string(denied)))
            for ceiling in data['ceiling_list']:
                rows.append(('ceiling', permission.dict_to_string(ceiling)))
            output = tabulate.tabulate(rows, tablefmt='plain')
    print(output)


def _boundary_delete_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary_id = _boundary_id(args, auth)
    response = auth.delete(f'{c.directory["boundary"]}/{boundary_id}')
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to delete boundary: {response.json()["title"]}')


def _boundary_create_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.post(f'{c.directory["boundary"]}', json={
        'name': args.name,
        'description': '' if args.description is None else args.description
    })
    if response.status_code != 201:
        raise exceptions.UI(f'Unable to create boundary: {response.json()["title"]}')


def _boundary_id(args, auth): 
    if args.id:
        boundary_id = args.id
    else:
        response = auth.get(auth.directory.boundary, params={'name': args.name})
        if response.status_code != 200:
            raise exceptions.UI(f'Unable to find boundary name="{args.name}"')
        boundary_id = response.json()['boundaries'][0]['id']
    return boundary_id

def _boundary_update_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary_id = _boundary_id(args, auth)
    response = auth.patch(f'{c.directory["boundary"]}/{boundary_id}', json={
        'description': '' if args.description is None else args.description
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update boundary: {response.json()["title"]}.')


def _boundary_denied_function(args):
    pass


def _boundary_ceiling_function(args):
    pass


def _add_boundary_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List boundaries we have access to')
    list_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    list_parser.add_argument('-n', '--name', type=str, help='Request boundaries that match this name.')
    list_parser.set_defaults(func=_boundary_list_function)

    read_parser = subparsers.add_parser('read', help='Show details on a specific boundary')
    read_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    read_parser.add_argument('id', type=int, help='Boundary id')
    read_parser.set_defaults(func=_boundary_read_function)

    create_parser = subparsers.add_parser('create', help='Create a new boundary')
    create_parser.add_argument('name', type=str, help='Name of boundary. Must be globally unique.')
    create_parser.add_argument('-d', '--description', type=str, help='Description')
    create_parser.set_defaults(func=_boundary_create_function)

    update_parser = subparsers.add_parser('update', help='Update description')
    group = update_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-n', '--name', type=str, help='Name of boundary.')
    group.add_argument('-i', '--id', type=int, help='Id of boundary.')
    update_parser.add_argument('-d', '--description', type=str, help='Description')
    update_parser.set_defaults(func=_boundary_update_function)

    denied_parser = subparsers.add_parser('denied', help='Update the list of denied permissions for boundary')
    group = denied_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-n', '--name', type=str, help='Name of boundary.')
    group.add_argument('-i', '--id', type=int, help='Id of boundary.')
    denied_parser.add_argument('-a', '--add', type=str, help='Add permission to denied list', nargs='*', default=[])
    denied_parser.add_argument('-d', '--del', type=str, help='Delete permission from denied list', nargs='*', default=[])
    denied_parser.add_argument('-s', '--set', type=str, help='Set denied list', nargs='*', default=[])
    denied_parser.set_defaults(func=_boundary_denied_function)

    ceiling_parser = subparsers.add_parser('ceiling', help='Update the list of celling permissions for boundary')
    group = ceiling_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-n', '--name', type=str, help='Name of boundary.')
    group.add_argument('-i', '--id', type=int, help='Id of boundary.')
    ceiling_parser.add_argument('-a', '--add', type=str, help='Add permission to ceiling list', nargs='*', default=[])
    ceiling_parser.add_argument('-d', '--del', type=str, help='Delete permission from celing list', nargs='*', default=[])
    ceiling_parser.add_argument('-s', '--set', type=str, help='Set ceiling list', nargs='*', default=[])
    ceiling_parser.set_defaults(func=_boundary_ceiling_function)

    delete_parser = subparsers.add_parser('delete', help='Delete an unused boundary')
    group = delete_parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-n', '--name', type=str, help='Name of boundary.')
    group.add_argument('-i', '--id', type=int, help='Id of boundary.')
    delete_parser.set_defaults(func=_boundary_delete_function)


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.set_defaults(func=_initialize_function)

    boundary_parser = subparsers.add_parser('boundary')
    _add_boundary_subparser(boundary_parser)
