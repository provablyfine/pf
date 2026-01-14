import json
import tabulate

from . import config
from . import client
from . import exceptions
from . import permission


def _boundaries(args, auth):
    params = {}
    if args.id is not None:
        params['id'] = args.id
    if args.name is not None:
        params['name'] = args.name
    response = auth.get(auth.directory.boundary, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to find boundary {",".join("=".join(kv) for kv in params.items())}')
    boundaries = response.json()['boundaries']
    return boundaries


def _boundary(args, auth):
    boundaries = _boundaries(args, auth)
    if len(boundaries) == 0:
        raise exceptions.UI('No boundary found')
    assert len(boundaries) == 1
    return boundaries[0]


def _boundary_id(args, auth):
    boundary = _boundary(args, auth)
    return boundary['id']

def _boundary_list_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundaries = _boundaries(args, auth)
    match args.format:
        case 'json':
            output = json.dumps(boundaries, indent=2)
        case 'text':
            rows = []
            for boundary in boundaries:
                rows.append([boundary['id'], boundary['name'], boundary['description']])
            output = tabulate.tabulate(rows, headers=['id', 'name', 'description'])
    print(output)


def _boundary_read_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary = _boundary(args, auth)
    match args.format:
        case 'json':
            output = json.dumps(boundary, indent=2)
        case 'text':
            rows = []
            rows.append(('id', boundary['id']))
            rows.append(('name', boundary['name']))
            rows.append(('description', boundary['description']))
            for denied in boundary['denied_list']:
                rows.append(('denied', permission.dict_to_string(denied)))
            for ceiling in boundary['ceiling_list']:
                rows.append(('ceiling', permission.dict_to_string(ceiling)))
            output = tabulate.tabulate(rows, tablefmt='plain')
    print(output)


def _boundary_delete_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary_id = _boundary_id(args, auth)
    response = auth.delete(f'{idb.directory.boundary}/{boundary_id}')
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to delete boundary: {response.json()["title"]}')


def _boundary_create_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.post(idb.directory.boundary, json={
        'name': args.name,
        'description': '' if args.description is None else args.description
    })
    if response.status_code != 201:
        raise exceptions.UI(f'Unable to create boundary: {response.json()["title"]}')



def _boundary_update_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary_id = _boundary_id(args, auth)
    response = auth.patch(f'{idb.directory.boundary}/{boundary_id}', json={
        'description': '' if args.description is None else args.description
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update boundary: {response.json()["title"]}.')


def _boundary_permission_function(args, name):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    boundary = _boundary(args, auth)
    permission_list = boundary[name]
    for added in args.add:
        to_add = permission.dict_from_string(added)
        permission_list.append(to_add)
    for deleted in args.delete:
        to_del = permission.dict_from_string(deleted)
        permission_list.remove(to_del)
    if args.set is not None:
        permission_list = args.set
    response = auth.patch(f'{idb.directory.boundary}/{boundary["id"]}', json={
        name: permission_list,
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update boundary: {response.json()["title"]}.')


def _boundary_denied_function(args):
    _boundary_permission_function(args, 'denied_list')


def _boundary_ceiling_function(args):
    _boundary_permission_function(args, 'ceiling_list')


def _add_filter_group(parser, required=False):
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument('-n', '--name', type=str, help='Name of boundary.')
    group.add_argument('-i', '--id', type=int, help='Id of boundary.')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List boundaries we have access to')
    _add_filter_group(list_parser)
    list_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    list_parser.set_defaults(func=_boundary_list_function)

    read_parser = subparsers.add_parser('read', help='Show details on a specific boundary')
    _add_filter_group(read_parser, required=True)
    read_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    read_parser.set_defaults(func=_boundary_read_function)

    create_parser = subparsers.add_parser('create', help='Create a new boundary')
    create_parser.add_argument('name', type=str, help='Name of boundary. Must be globally unique.')
    create_parser.add_argument('-d', '--description', type=str, help='Description')
    create_parser.set_defaults(func=_boundary_create_function)

    update_parser = subparsers.add_parser('update', help='Update description')
    _add_filter_group(update_parser, required=True)
    update_parser.add_argument('-d', '--description', type=str, help='Description')
    update_parser.set_defaults(func=_boundary_update_function)

    denied_parser = subparsers.add_parser('denied', help='Update the list of denied permissions for boundary')
    _add_filter_group(denied_parser, required=True)
    denied_parser.add_argument('-a', '--add', type=str, help='Add permission to denied list', nargs='*', default=[])
    denied_parser.add_argument('-d', '--del', dest='delete', type=str, help='Delete permission from denied list', nargs='*', default=[])
    denied_parser.add_argument('-s', '--set', type=str, help='Set denied list', nargs='*', default=None)
    denied_parser.set_defaults(func=_boundary_denied_function)

    ceiling_parser = subparsers.add_parser('ceiling', help='Update the list of celling permissions for boundary')
    _add_filter_group(ceiling_parser, required=True)
    ceiling_parser.add_argument('-a', '--add', type=str, help='Add permission to ceiling list', nargs='*', default=[])
    ceiling_parser.add_argument('-d', '--del', dest='delete', type=str, help='Delete permission from celing list', nargs='*', default=[])
    ceiling_parser.add_argument('-s', '--set', type=str, help='Set ceiling list', nargs='*', default=None)
    ceiling_parser.set_defaults(func=_boundary_ceiling_function)

    delete_parser = subparsers.add_parser('delete', help='Delete an unused boundary')
    _add_filter_group(delete_parser, required=True)
    delete_parser.set_defaults(func=_boundary_delete_function)
