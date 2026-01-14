import json
import tabulate

from . import config
from . import client
from . import exceptions


def _tags(args, auth):
    params = {}
    if args.id is not None:
        params['id'] = args.id
    if args.name is not None:
        params['name'] = args.name
    if args.value is not None:
        params['value'] = args.value
    response = auth.get(auth.directory.tag, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f'Unable to find tags {",".join("=".join(kv) for kv in params.items())}')
    tags = response.json()['tags']
    return tags


def tag_list_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    auth = idb.session_auth(c.session_key)
    tags = _tags(args, auth)
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
        raise exceptions.UI(f'Unable to create boundary: {response.json()["title"]}')


def _add_filter_group(parser, required=False):
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument('-i', '--id', type=int, help='Id of tag.')
    group.add_argument('-n', '--name', type=str, help='Name of tag.')
    group.add_argument('-v', '--value', type=str, help='Value of tag.')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser('list', help='List tags we have access to')
    _add_filter_group(list_parser)
    list_parser.add_argument('-s', '--sort', choices=['id', 'name', 'value'], default='name', help='Sort criterion. Default: %(default)s')
    list_parser.add_argument('-q', '--quiet', help='Equivalent to -f quiet', action='store_true')
    list_parser.add_argument('-f', '--format', choices=['json', 'text', 'quiet'], default='text', help='Output format')
    list_parser.set_defaults(func=tag_list_function)

    create_parser = subparsers.add_parser('create', help='Create a new tag')
    create_parser.add_argument('kv', metavar='name=value', type=str, help='Name/value pair for tag. The value pair must be globally unique.')
    create_parser.set_defaults(func=_tag_create_function)

