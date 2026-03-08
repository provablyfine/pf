import sys
import json

import yaml
import tabulate

from . import config
from . import client
from . import exceptions
from . import grant
from . import yaml_utils


def _boundaries(auth, id=None, name=None):
    params = {}
    if id is not None:
        params['id'] = id
    if name is not None:
        params['name'] = name
    response = auth.get(auth.directory.boundary, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to find boundary. {response.json()["title"]}')
    boundaries = response.json()['boundaries']
    return boundaries


def _boundary(auth, id):
    boundaries = _boundaries(auth, id=id)
    if len(boundaries) == 0:
        raise exceptions.UI('No boundary found')
    assert len(boundaries) == 1
    return boundaries[0]


def _boundary_list_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundaries = _boundaries(auth, id=args.id, name=args.name)
    match args.sort:
        case 'id':
            sort_function = lambda b: b['id']
        case 'name':
            sort_function = lambda b: (b['name'], b['id'])
        case _:
            assert False
    if args.quiet:
        args.format = 'quiet'
    match args.format:
        case 'quiet':
            output = '\n'.join(str(b['id']) for b in boundaries)
        case 'json':
            output = json.dumps(boundaries, indent=2)
        case 'yaml':
            output = yaml_utils.dump(boundaries)
        case 'text':
            rows = []
            for boundary in boundaries:
                rows.append([boundary['id'], boundary['name'], boundary['description']])
            if len(rows) == 0:
                output = ''
            else:
                output = tabulate.tabulate(rows, headers=['id', 'name', 'description'], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _boundary_read_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary = _boundary(auth, args.id)
    match args.format:
        case 'json':
            output = json.dumps(boundary, indent=2)
        case 'yaml':
            output = yaml_utils.dump(boundary)
        case 'text':
            rows = []
            rows.append(['id', boundary['id']])
            rows.append(['name', boundary['name']])
            rows.append(['description', boundary['description']])
            if boundary['ceiling_list'] is None:
                rows.append(['ceiling', '*'])
            else:
                for g in boundary['ceiling_list']:
                    type, filter, permission = grant.to_text(g)
                    rows.append(['ceiling', f'type:       {type}'])
                    rows.append(['',        f'filter:     {filter}'])
                    rows.append(['',        f'permission: {permission}'])
            for g in boundary['denied_list']:
                type, filter, permission = grant.to_text(g)
                rows.append(['denied',  f'type:       {type}'])
                rows.append(['',        f'filter:     {filter}'])
                rows.append(['',        f'permission: {permission}'])
            output = tabulate.tabulate(rows, tablefmt='plain')
        case _:
            assert False
    print(output)


def _boundary_delete_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.delete(f'{idb.directory.boundary}/{args.id}')
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to delete boundary. {response.json()["title"]}')


def _boundary_create_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.post(idb.directory.boundary, json={
        'name': args.name,
        'description': '' if args.description is None else args.description
    })
    if response.status_code != 201:
        raise exceptions.UI(f'Unable to create boundary. {response.json()["title"]}')



def _boundary_update_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    query = {}
    if args.name is not None:
        query['name'] = args.name
    if args.description is not None:
        query['description'] = args.description
    response = auth.patch(f'{idb.directory.boundary}/{args.id}', json=query)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update boundary. {response.json()["title"]}.')


def _boundary_grant_function(args, action, grant, field_name):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary = _boundary(auth, args.id)

    match action:
        case 'add':
            grant_list = [grant] if boundary[field_name] is None else boundary[field_name] + [grant]
        case 'del':
            grant_list = [g for g in boundary[field_name] if g != grant]
        case 'set':
            grant_list = grant
        case _:
            assert False

    response = auth.patch(f'{idb.directory.boundary}/{boundary["id"]}', json={
        field_name: grant_list,
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update boundary. {response.json()["title"]}.')


def _boundary_denied_function(args, action, grant):
    _boundary_grant_function(args, action, grant, 'denied_list')


def _boundary_ceiling_function(args, action, grant):
    _boundary_grant_function(args, action, grant, 'ceiling_list')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List boundaries we have access to')
    group = list_parser.add_argument_group(title='Filter criteria')
    group.add_argument('-n', '--name', type=str, help='Name of boundary.')
    group.add_argument('-i', '--id', type=int, help='Id of boundary.')
    group = list_parser.add_argument_group(title='Formatting criteria')
    group.add_argument('-s', '--sort', choices=['id', 'name'], default='name', help='Sort criterion. Default: %(default)s')
    group.add_argument('-q', '--quiet', help='Equivalent to -f quiet', action='store_true')
    group.add_argument('-f', '--format', choices=['json', 'text', 'quiet'], default='text', help='Output format')
    list_parser.set_defaults(func=_boundary_list_function)

    read_parser = subparsers.add_parser('read', help='Show details on a specific boundary')
    read_parser.add_argument('-i', '--id', type=int, help='Id of boundary.', required=True)
    read_parser.add_argument('-f', '--format', choices=['json', 'yaml', 'text'], default='text', help='Output format')
    read_parser.set_defaults(func=_boundary_read_function)

    create_parser = subparsers.add_parser('create', help='Create a new boundary')
    create_parser.add_argument('-n', '--name', type=str, help='Name of boundary. Must be globally unique.', required=True)
    create_parser.add_argument('-d', '--description', type=str, help='Description')
    create_parser.set_defaults(func=_boundary_create_function)

    update_parser = subparsers.add_parser('update', help='Update description')
    update_parser.add_argument('-i', '--id', type=int, help='Id of boundary.', required=True)
    update_parser.add_argument('-n', '--name', type=str, help='Name')
    update_parser.add_argument('-d', '--description', type=str, help='Description')
    update_parser.set_defaults(func=_boundary_update_function)

    denied_parser = subparsers.add_parser('denied', help='Update the list of denied grants for boundary')
    denied_parser.add_argument('-i', '--id', type=int, help='Id of boundary.', required=True)
    grant.add_parser(denied_parser, _boundary_denied_function)

    ceiling_parser = subparsers.add_parser('ceiling', help='Update the list of celling permissions for boundary')
    ceiling_parser.add_argument('-i', '--id', type=int, help='Id of boundary.', required=True)
    grant.add_parser(ceiling_parser, _boundary_ceiling_function)

    delete_parser = subparsers.add_parser('delete', help='Delete an unused boundary')
    delete_parser.add_argument('-i', '--id', type=int, help='Id of boundary.', required=True)
    delete_parser.set_defaults(func=_boundary_delete_function)
