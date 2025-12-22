import requests
import json
import tabulate

from . import config
from . import exceptions

def _initialize_function(args):
    c = config.Config.load(args.config)
    response = requests.post(c.directory['initialize'])
    if response.status_code == 204:
        raise exceptions.UI(f'Unable to initialize app: it is already initialized.')
    response.raise_for_status()
    data = response.json()
    if args.format == 'json':
        print(json.dumps(data, indent=2))
    elif args.format == 'text':
        rows = [['identity_id', data['identity_id']], ['invitation', f'{data["key_id"]}:{data["key"]}']]
        print(tabulate.tabulate(rows))


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.add_argument('--format', choices=['json', 'text'], default='text', help='Initialize idb server')
    initialize_parser.set_defaults(func=_initialize_function)

    #identity_create
