import json
import tabulate

from . import config
from . import client
from . import exceptions
from . import grant
from . import yaml_utils
from . import grant


def _roles(auth, id=None, name=None):
    params = {}
    if id is not None:
        params['id'] = id
    if name is not None:
        params['name'] = name
    response = auth.get(auth.directory.role, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to find role {",".join(f'{k}={v}' for k, v in params.items())}')
    roles = response.json()['roles']
    return roles


def _role(args, auth):
    roles = _roles(auth, id=args.id)
    if len(roles) == 0:
        raise exceptions.UI('No role found')
    assert len(roles) == 1
    return roles[0]


def _role_list_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    roles = _roles(auth, id=args.id, name=args.name)
    match args.sort:
        case 'id':
            sort_function = lambda i: i['id']
        case 'name':
            sort_function = lambda i: (i['name'], i['id'])
        case _:
            assert False
    if args.quiet:
        args.format = 'quiet'
    match args.format:
        case 'quiet':
            output = '\n'.join(str(r['id']) for r in roles)
        case 'json':
            output = json.dumps(roles, indent=2)
        case 'yaml':
            output = yaml_utils.dump(roles)
        case 'text':
            rows = []
            for role in roles:
                rows.append([role['id'], role['name'], role['description']])
            if len(rows) == 0:
                output = ''
            else:
                output = tabulate.tabulate(rows, headers=['id', 'name', 'description'], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _role_read_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    role = _role(args, auth)
    match args.format:
        case 'json':
            output = json.dumps(role, indent=2)
        case 'yaml':
            output = yaml_utils.dump(role)
        case 'text':
            rows = []
            rows.append(['id', role['id']])
            rows.append(['name', role['name']])
            rows.append(['description', role['description']])
            for m in role['member_list']:
                rows.append(['member', m['name']])
            for g in role['grant_list']:
                type, filter, permission = grant.to_text(g)
                rows.append(['grant', f'type:       {type}'])
                rows.append(['',      f'filter:     {filter}'])
                rows.append(['',      f'permission: {permission}'])
            output = tabulate.tabulate(rows, tablefmt='plain')
        case _:
            assert False
    print(output)


def _role_delete_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.delete(f'{api.directory.role}/{args.id}')
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to delete role. {response.json()["title"]}')


def _role_create_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.post(api.directory.role, json={
        'name': args.name,
        'description': '' if args.description is None else args.description
    })
    if response.status_code != 201:
        raise exceptions.UI(f'Unable to create role. {response.json()["title"]}')


def _role_update_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    query = {}
    if args.name is not None:
        query['name'] = args.name
    if args.description is not None:
        query['description'] = args.description
    response = auth.patch(f'{api.directory.role}/{args.id}', json=query)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update role. {response.json()["title"]}.')


def _role_grant_function(args, action, grant):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    role = _role(args, auth)

    match action:
        case 'add':
            grant_list = role['grant_list'] + [grant]
        case 'del':
            grant_list = [g for g in role['grant_list'] if g != grant]
        case 'set':
            grant_list = grant
        case _:
            assert False

    response = auth.patch(f'{api.directory.role}/{role["id"]}', json={
        'grant_list': grant_list,
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update role. {response.json()["title"]}.')


def _role_member_function(args):

    def to_dict(member):
        if member.isdigit():
            return {'id': int(member)}
        else:
            return {'name': member}

    def is_equal(a, b):
        if 'id' in a and 'id' in b and a['id'] == b['id']:
            return True
        if 'name' in a and 'name' in b and a['name'] == b['name']:
            return True
        return False

    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    role = _role(args, auth)
    member_list = role['member_list']

    for added in args.add:
        member = to_dict(added)
        if not any(is_equal(member, m) for m in member_list):
            member_list.append(member)

    for deleted in args.delete:
        member = to_dict(deleted)
        member_list = [m for m in member_list if not is_equal(m, member)]

    if args.set is not None:
        member_list = [to_dict(m) for m in args.set]

    response = auth.patch(f'{api.directory.role}/{role["id"]}', json={
        'member_list': member_list,
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update role. {response.json()["title"]}.')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List roles we have access to')
    group = list_parser.add_argument_group(title='Filter criteria')
    group.add_argument('-n', '--name', type=str, help='Name of role.')
    group.add_argument('-i', '--id', type=int, help='Id of role.')
    group = list_parser.add_argument_group(title='Formatting criteria')
    group.add_argument('-s', '--sort', choices=['id', 'name'], default='name', help='Sort criterion. Default: %(default)s')
    group.add_argument('-q', '--quiet', help='Equivalent to -f quiet', action='store_true')
    group.add_argument('-f', '--format', choices=['json', 'yaml', 'text', 'quiet'], default='text', help='Output format')
    list_parser.set_defaults(func=_role_list_function)

    read_parser = subparsers.add_parser('read', help='Show details on a specific role')
    read_parser.add_argument('-i', '--id', type=int, help='Id of role.', required=True)
    read_parser.add_argument('-f', '--format', choices=['json', 'yaml', 'text'], default='text', help='Output format')
    read_parser.set_defaults(func=_role_read_function)

    create_parser = subparsers.add_parser('create', help='Create a new role')
    create_parser.add_argument('-n', '--name', type=str, help='Name of role. Must be globally unique.', required=True)
    create_parser.add_argument('-d', '--description', type=str, help='Description')
    create_parser.set_defaults(func=_role_create_function)

    delete_parser = subparsers.add_parser('delete', help='Delete an unused role')
    delete_parser.add_argument('-i', '--id', type=int, help='Id of role.', required=True)
    delete_parser.set_defaults(func=_role_delete_function)

    update_parser = subparsers.add_parser('update', help='Update a role')
    update_parser.add_argument('-i', '--id', type=int, help='Id of role.', required=True)
    update_parser.add_argument('-n', '--name', type=str, help='Name')
    update_parser.add_argument('-d', '--description', type=str, help='Description')
    update_parser.set_defaults(func=_role_update_function)

    grant_parser = subparsers.add_parser('grant', help='Update the list of grants granted by role')
    grant_parser.add_argument('-i', '--id', type=int, help='Id of role.', required=True)
    grant.add_parser(grant_parser, _role_grant_function)

    members_parser = subparsers.add_parser('member', help='Update the list of members assigned to this role')
    members_parser.add_argument('-i', '--id', type=int, help='Id of role.', required=True)
    members_parser.add_argument('-a', '--add', type=str, help='Add member to role', nargs='*', default=[])
    members_parser.add_argument('-d', '--del', dest='delete', type=str, help='Delete member from role', nargs='*', default=[])
    members_parser.add_argument('-s', '--set', type=str, help='Set member list', nargs='*', default=None)
    members_parser.set_defaults(func=_role_member_function)
