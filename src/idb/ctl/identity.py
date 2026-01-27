import json
import tabulate

from . import config
from . import client
from . import exceptions
from . import permission


def _identities(auth, id:int=None, name:str=None, tag_id:int=None, tag_name:str=None, boundary_id:int=None, boundary_name:str=None):
    params = {}
    if id is not None:
        params['id'] = id
    if name is not None:
        params['name'] = name
    if tag_id is not None:
        params['tag_id'] = tag_id
    if tag_name is not None:
        params['tag_name'] = tag_name
    if boundary_id is not None:
        params['boundary_id'] = boundary_id
    if boundary_name is not None:
        params['boundary_name'] = boundary_name
    response = auth.get(auth.directory.identity, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to find identity {",".join("=".join(kv) for kv in params.items())}')
    identities = response.json()['identities']
    return identities


def _identity(args, auth):
    identities = _identities(auth, id=args.id)
    if len(identities) == 0:
        raise exceptions.UI('No identity found')
    assert len(identities) == 1
    return identities[0]


def _identity_list_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    identities = _identities(auth, id=args.id, name=args.name, tag_id=args.tag_id, tag_name=args.tag_name, boundary_id=args.boundary_id, boundary_name=args.boundary_name)
    match args.format:
        case 'json':
            output = json.dumps(identities, indent=2)
        case 'text':
            rows = []
            for identity in identities:
                rows.append([identity['id'], identity['name'], len(identity['tags']), len(identity['boundaries'])])
            if len(rows) == 0:
                output = ''
            else:
                output = tabulate.tabulate(rows, headers=['id', 'name', 'ntags', 'nboundaries'], maxcolwidths=80)
    if output:
        print(output)


def _identity_read_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    identity = _identity(args, auth)
    match args.format:
        case 'json':
            output = json.dumps(identity, indent=2)
        case 'text':
            rows = []
            rows.append(('id', identity['id']))
            rows.append(('name', identity['name']))
            for t in identity['tags']:
                rows.append(('tag', f'{t["name"]}={t["value"]}'))
            for b in identity['boundaries']:
                rows.append(('boundary', b['name']))
            output = tabulate.tabulate(rows, tablefmt='plain')
    print(output)


def _identity_delete_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    response = auth.delete(f'{idb.directory.identity}/{args.id}')
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to delete identity: {response.json()["title"]}')


def _identity_create_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    def boundary(s: str):
        if s.isdigit():
            return {'id': int(s)}
        else:
            return {'name': s}
    boundaries = [boundary(s) for s in args.boundary]
    response = auth.post(idb.directory.identity, json={
        'name': args.name,
        'boundaries': boundaries
    })
    if response.status_code != 201:
        raise exceptions.UI(f'Unable to create identity: {response.json()["title"]}')


def _identity_update_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    query = {}
    if args.name is not None:
        query['name'] = args.name
    response = auth.patch(f'{idb.directory.identity}/{args.id}', json=query)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update identity: {response.json()["title"]}.')


def _identity_tag_function(args):

    def _is_equal(a: dict, b: dict):
        if 'id' in a and 'id' in b and a['id'] == b['id']:
            return True
        if 'name' in a and 'name' in b and a['name'] == b['name'] \
                and 'value' in a and 'value' in b and a['value'] == b['value']:
            return True
        return False

    def _tag(tag: str):
        if tag.isdigit():
            return {'id': int(tag)}
        else:
            equal = tag.find('=')
            if equal == -1:
                raise exceptions.UI(f'Tag format is name=value, not {tag}')
            name = tag[:equal]
            value = tag[equal+1:]
            return {'name': name, 'value': value}

    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    identity = _identity(args, auth)

    tags = identity['tags']
    to_add = [_tag(tag) for tag in args.add]
    to_delete = [_tag(tag) for tag in args.delete]
    for tag in to_delete:
        tags = [t for t in tags if not _is_equal(t, tag)]
    tags = [{'id': tag['id']} for tag in tags]
    for tag in to_add:
        if any(_is_equal(tag, t) for t in tags):
            continue
        tags.append(tag)
    if args.set is not None:
        tags = [_tag(tag) for tag in args.set]
    response = auth.patch(f'{idb.directory.identity}/{identity["id"]}', json={
        'tags': tags,
    })
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to update identity: {response.json()["title"]}.')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List identities we have access to')
    group = list_parser.add_argument_group(title='Filter criteria')
    group.add_argument('-i', '--id', type=int, help='Id of identity')
    group.add_argument('-n', '--name', type=str, help='Name of identity')
    group.add_argument('--tag-id', type=str, help='Id of tag applied to identity', nargs='*')
    group.add_argument('--tag-name', type=str, help='Name of tag applied to identity', nargs='*')
    group.add_argument('--boundary-id', type=str, help='Id of boundary applied to identity', nargs='*')
    group.add_argument('--boundary-name', type=str, help='Name of boundary applied to identity', nargs='*')
    group = list_parser.add_argument_group(title='Formatting criteria')
    group.add_argument('-s', '--sort', choices=['id', 'name', 'value'], default='name', help='Sort criterion. Default: %(default)s')
    group.add_argument('-q', '--quiet', help='Equivalent to -f quiet', action='store_true')
    group.add_argument('-f', '--format', choices=['json', 'text', 'quiet'], default='text', help='Output format')
    list_parser.set_defaults(func=_identity_list_function)

    read_parser = subparsers.add_parser('read', help='Show details on a specific identity')
    read_parser.add_argument('-i', '--id', type=int, help='Id of identity')
    read_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    read_parser.set_defaults(func=_identity_read_function)

    create_parser = subparsers.add_parser('create', help='Create a new identity')
    create_parser.add_argument('-n', '--name', type=str, help='Name of identity. Must be globally unique.')
    create_parser.add_argument('-b', '--boundary', help='Boundary to enforce on newly-created user', nargs='*', default=[])
    create_parser.set_defaults(func=_identity_create_function)

    delete_parser = subparsers.add_parser('delete', help='Delete an unused identity')
    delete_parser.add_argument('-i', '--id', type=int, help='Id of identity')
    delete_parser.set_defaults(func=_identity_delete_function)

    update_parser = subparsers.add_parser('update', help='Update an existing identity')
    update_parser.add_argument('-i', '--id', type=int, help='Id of identity')
    update_parser.add_argument('-n', '--name', help='New name of identity')
    update_parser.set_defaults(func=_identity_update_function)

    tag_parser = subparsers.add_parser('tag', help='Update the list of tags assigned to an identity')
    tag_parser.add_argument('-i', '--id', type=int, help='Id of identity')
    tag_parser.add_argument('-a', '--add', type=str, help='Add tag to identity', nargs='*', default=[])
    tag_parser.add_argument('-d', '--del', dest='delete', type=str, help='Delete tag from identity', nargs='*', default=[])
    tag_parser.add_argument('-s', '--set', type=str, help='Set list of tags', nargs='*', default=None)
    tag_parser.set_defaults(func=_identity_tag_function)
