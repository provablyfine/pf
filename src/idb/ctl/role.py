import json
import tabulate

from . import config
from . import client
from . import exceptions
from . import permission


def _roles(args, auth):
    params = {}
    if args.id is not None:
        params['id'] = args.id
    if args.name is not None:
        params['name'] = args.name
    response = auth.get(auth.directory.role, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to find role {",".join("=".join(kv) for kv in params.items())}')
    roles = response.json()['roles']
    return roles


def _role(args, auth):
    roles = _roles(args, auth)
    if len(roles) == 0:
        raise exceptions.UI('No role found')
    assert len(roles) == 1
    return roles[0]


def _role_id(args, auth):
    role = _role(args, auth)
    return role['id']


def _role_list_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    roles = _roles(args, auth)
    match args.format:
        case 'json':
            output = json.dumps(roles, indent=2)
        case 'text':
            rows = []
            for role in roles:
                rows.append([role['id'], role['name'], role['description']])
            if len(rows) == 0:
                output = ''
            else:
                output = tabulate.tabulate(rows, headers=['id', 'name', 'description'], maxcolwidths=80)
    if output:
        print(output)


def _role_read_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    role = _role(args, auth)
    match args.format:
        case 'json':
            output = json.dumps(role, indent=2)
        case 'text':
            rows = []
            rows.append(('id', role['id']))
            rows.append(('name', role['name']))
            rows.append(('description', role['description']))
            for p in role['permissions']:
                rows.append(('permission', permission.dict_to_string(p)))
            for member in role['members']:
                rows.append(('member', member['name']))
            output = tabulate.tabulate(rows, tablefmt='plain')
    print(output)


def _role_delete_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    role_id = _role_id(args, auth)
    response = auth.delete(f'{idb.directory.role}/{role_id}')
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to delete role: {response.json()["title"]}')


def _role_create_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.post(idb.directory.role, json={
        'name': args.name,
        'description': '' if args.description is None else args.description
    })
    if response.status_code != 201:
        raise exceptions.UI(f'Unable to create role: {response.json()["title"]}')


def _role_update_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    role_id = _role_id(args, auth)
    response = auth.patch(f'{idb.directory.role}/{role_id}', json={
        'description': args.description,
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update role: {response.json()["title"]}.')


def _role_permission_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    role = _role(args, auth)
    permission_list = role['permissions']
    for added in args.add:
        to_add = permission.dict_from_string(added)
        permission_list.append(to_add)
    for deleted in args.delete:
        to_del = permission.dict_from_string(deleted)
        # XXX: does remove work here ?
        permission_list.remove(to_del)
    if args.set is not None:
        permission_list = [permission.dict_from_string(p) for p in args.set]
    response = auth.patch(f'{idb.directory.role}/{role["id"]}', json={
        'permissions': permission_list,
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update role: {response.json()["title"]}.')


def _add_filter_group(parser, required=False):
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument('-n', '--name', type=str, help='Name of role.')
    group.add_argument('-i', '--id', type=int, help='Id of role.')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List roles we have access to')
    _add_filter_group(list_parser)
    list_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    list_parser.set_defaults(func=_role_list_function)

    read_parser = subparsers.add_parser('read', help='Show details on a specific role')
    _add_filter_group(read_parser, required=True)
    read_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    read_parser.set_defaults(func=_role_read_function)

    create_parser = subparsers.add_parser('create', help='Create a new role')
    create_parser.add_argument('name', type=str, help='Name of role. Must be globally unique.')
    create_parser.add_argument('-d', '--description', type=str, help='Description')
    create_parser.set_defaults(func=_role_create_function)

    delete_parser = subparsers.add_parser('delete', help='Delete an unused role')
    _add_filter_group(delete_parser, required=True)
    delete_parser.set_defaults(func=_role_delete_function)

    update_parser = subparsers.add_parser('update', help='Update a role')
    _add_filter_group(update_parser, required=True)
    update_parser.add_argument('-d', '--description', type=str, help='Description', required=True)
    update_parser.set_defaults(func=_role_update_function)

    permissions_parser = subparsers.add_parser('permission', help='Update the list of permissions granted by role')
    _add_filter_group(permissions_parser, required=True)
    permissions_parser.add_argument('-a', '--add', type=str, help='Add permission to role', nargs='*', default=[])
    permissions_parser.add_argument('-d', '--del', dest='delete', type=str, help='Delete permission from role', nargs='*', default=[])
    permissions_parser.add_argument('-s', '--set', type=str, help='Set permission list', nargs='*', default=None)
    permissions_parser.set_defaults(func=_role_permission_function)
