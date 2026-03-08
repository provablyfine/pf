import os.path
import os
import sys
import json

import yaml
import pydantic

from . import exceptions


def add_parser(parser, f):
    def _read_grant_stdin():
        data = sys.stdin.read()
        try:
            grant = json.loads(data)
        except:
            try:
                grant = yaml.safe_load(data)
            except:
                raise exceptions.UI('Unable to read grant from stdin');
        return grant
    def _do(args):
        grant = _read_grant_stdin()
        if args.add:
            f(args, 'add', grant)
        if args.delete:
            f(args, 'del', grant)
        if args.set:
            f(args, 'set', grant)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', '--add', action='store_true', help='Add one grant')
    group.add_argument('-d', '--delete', action='store_true', help='Delete one grant')
    group.add_argument('-s', '--set', action='store_true', help='Set a list of grants')
    parser.set_defaults(func=_do)
