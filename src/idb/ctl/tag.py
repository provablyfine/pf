import json
import tabulate

from . import config
from . import client
from . import exceptions


def _tags(auth, params):
    response = auth.get(auth.directory.tag, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to find tags {",".join("=".join(kv) for kv in params.items())}')
    tags = response.json()['tags']
    return tags


def _tags_kv(args, auth):
    params = {}
    if args.id is not None:
        params['id'] = args.id
    if args.kv is not None:
        kv = args.kv.split('=')
        if len(kv) != 2:
            raise exceptions.UI('kv must match name=value syntax')
        name, value = kv
        params['name'] = name
        params['value'] = value
    return _tags(auth, params)


def _tags_name_value(args, auth):
    params = {}
    if args.id is not None:
        params['id'] = args.id
    if args.name is not None:
        params['name'] = atgs.name
    if args.value is not None:
        params['value'] = args.value
    return _tags(auth, params)


def _tag(args, auth):
    tags = _tags_kv(args, auth)
    if len(tags) == 0:
        raise exceptions.UI('No tag found')
    assert len(tags) == 1
    return tags[0]


def tag_list_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    tags = _tags_name_value(args, auth)
    match args.sort:
        case 'id':
            sort_function = lambda t: t['id']
        case 'name':
            sort_function = lambda t: (t['name'], t['value'], t['id'])
        case 'value':
            sort_function = lambda t: (t['value'], t['name'], t['id'])
    tags = sorted(tags, key=sort_function)
    if args.quiet:
        args.format = 'quiet'
    match args.format:
        case 'quiet':
            output = '\n'.join(t['id'] for t in tags)
        case 'json':
            output = json.dumps(tags, indent=2)
        case 'text':
            rows = []
            for tag in tags:
                rows.append([tag['id'], tag['name'], tag['value']])
            output = tabulate.tabulate(rows, headers=['id', 'name', 'value'])
        case _:
            assert False, args.format
    print(output)


def _tag_create_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    kv = args.kv.split('=')
    if len(kv) != 2:
        raise exceptions.UI('Name/value pair must be provided as name=value')
    name, value = kv
    response = auth.post(idb.directory.tag, json={
        'name': name,
        'value': value,
    })
    if response.status_code != 201:
        raise exceptions.UI(f'Unable to create tag: {response.json()["title"]}')


def _tag_delete_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    tag = _tag(args, auth)
    response = auth.delete(f'{idb.directory.tag}/{tag["id"]}')
    if response.status_code != 204:
        raise exceptions.UI(f'Unable to delete tag: {response.json()["title"]}')


def _add_filter_group(parser, required=False):
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument('-i', '--id', type=int, help='Id of tag.')
    group.add_argument('--kv', type=str, help='Name/value of tag.')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List tags we have access to')
    group = list_parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--id', type=int, help='Id of tag.')
    group.add_argument('-n', '--name', type=str, help='Name of tag.')
    group.add_argument('-v', '--value', type=str, help='Value of tag.')
    list_parser.add_argument('-s', '--sort', choices=['id', 'name', 'value'], default='name', help='Sort criterion. Default: %(default)s')
    list_parser.add_argument('-q', '--quiet', help='Equivalent to -f quiet', action='store_true')
    list_parser.add_argument('-f', '--format', choices=['json', 'text', 'quiet'], default='text', help='Output format')
    list_parser.set_defaults(func=tag_list_function)

    create_parser = subparsers.add_parser('create', help='Create a new tag')
    create_parser.add_argument('kv', metavar='name=value', type=str, help='Name/value pair for tag. The value pair must be globally unique.')
    create_parser.set_defaults(func=_tag_create_function)

    delete_parser = subparsers.add_parser('delete', help='Delete a tag')
    _add_filter_group(delete_parser, required=True)
    delete_parser.set_defaults(func=_tag_delete_function)
