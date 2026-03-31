import argparse
import logging
import os
import os.path
import sys
import traceback

from ... import client
from . import admin_cli

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "pf", "config.json")


def _do_main(args):
    if args.debug > 0:
        match args.debug:
            case 3:
                level = logging.DEBUG
            case 2:
                level = logging.INFO
            case 1:
                level = logging.WARN
            case _:
                assert args.debug > 3
                level = logging.DEBUG

        logging.basicConfig(stream=sys.stdout, level=level)

    try:
        args.func(args)
        exitcode = 0
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)


def pfa():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", help="Increase debugging level", action="count", default=0)
    parser.add_argument("-c", "--config", help="configuration file", default=_DEFAULT_CONFIG)
    admin_cli.add_subparsers(parser)

    args = parser.parse_args()

    _do_main(args)
