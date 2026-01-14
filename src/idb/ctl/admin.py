from . import config
from . import exceptions
from . import client
from . import boundary
from . import tag


def _initialize_function(args):
    c = config.Config.load(args.config)
    idb = client.Client(c)
    response = idb.no_auth.post(idb.directory.initialize)
    if response.status_code == 204:
        raise exceptions.UI('Unable to initialize app: it is already initialized.')
    if response.status_code != 200:
        raise exceptions.UI('Unable to initialize app: expected error.')
    data = response.json()
    print(data["key"]['k'])


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.set_defaults(func=_initialize_function)

    boundary_parser = subparsers.add_parser('boundary', help='View and edit boundaries')
    boundary.add_subparser(boundary_parser)

    tag_parser = subparsers.add_parser('tag', help='View and edit tags')
    tag.add_subparser(tag_parser)
