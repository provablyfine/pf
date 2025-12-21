import requests

from . import config

def _initialize_function(args):
    c = config.Config.load(args.config)
    response = requests.post(c.directory['initialize'])
    print(response.text, response.status_code)
    response.raise_for_status()


def add_subparsers(parser):
    subparsers = parser.add_subparsers()

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.set_defaults(func=_initialize_function)

    #identity_create
