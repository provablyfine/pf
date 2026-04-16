import argparse
import json
import sys
import typing

import yaml

from .. import client


def add_parser(parser: argparse.ArgumentParser, f: typing.Callable[..., None]) -> None:
    def _read_grant_stdin():
        data = sys.stdin.read()
        try:
            grant = json.loads(data)
        except Exception:
            try:
                grant = yaml.safe_load(data)
            except Exception:
                raise client.exceptions.UI("Unable to read grant from stdin")
        return grant

    def _do(args: argparse.Namespace) -> None:
        grant = _read_grant_stdin()
        if args.add:
            f(args, "add", grant)
        if args.delete:
            f(args, "del", grant)
        if args.set:
            if not isinstance(grant, list):
                grant = [grant]
            f(args, "set", grant)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--add", action="store_true", help="Add one grant")
    group.add_argument("-d", "--delete", action="store_true", help="Delete one grant")
    group.add_argument("-s", "--set", action="store_true", help="Set a list of grants")
    parser.set_defaults(func=_do)
