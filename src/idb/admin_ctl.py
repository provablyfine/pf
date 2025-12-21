def _initialize_function(args):
    pass


def add_subparsers(parser):
    subparsers = parser.add_subparsers()

    initialize_parser = subparsers.add_parser('initialize')
    initialize_parser.set_defaults(func=_initialize_function)

    #identity_create
