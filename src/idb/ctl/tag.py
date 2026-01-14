def tag_list_function(args):
    pass

def _add_filter_group(parser, required=False):
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument('-i', '--id', type=int, help='Id of tag.')
    group.add_argument('-n', '--name', type=str, help='Name of tag.')
    group.add_argument('-v', '--value', type=str, help='Value of tag.')


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    tag_parser = subparsers.add_parser('list', help='List tags we have access to')
    _add_filter_group(tag_parser)
    tag_parser.add_argument('-f', '--format', choices=['json', 'text'], default='text', help='Output format')
    tag_parser.set_defaults(func=tag_list_function)
