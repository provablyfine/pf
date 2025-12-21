import requests

from . import config
from . import exceptions

def _initialize_function(args):
    c = config.Config.load(args.config)
    response = requests.post(c.directory['initialize'])
    if response.status_code == 204:
        raise exceptions.UI(f'Unable to initialize app: it is already initialized.')
    response.raise_for_status()
    data = response.json()
    print(f'{data["key_id"]}:{data["key"]}')


def add_subparsers(parser):
    subparsers = parser.add_subparsers()

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.set_defaults(func=_initialize_function)

    #identity_create
