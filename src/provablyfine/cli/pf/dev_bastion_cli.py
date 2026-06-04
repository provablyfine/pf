import argparse
import asyncio
import sys
import traceback

import provablyfine_client as pfc

from ... import log
from . import bastion_cli


def _register_function(args: argparse.Namespace) -> None:
    asyncio.run(bastion_cli.register_async(args.socket_path, args.url, "dev", args.port))


def _connect_function(args: argparse.Namespace) -> None:
    asyncio.run(bastion_cli.connect_async(args.socket_path, args.url, "dev", args.hostname))


def _do_main(args: argparse.Namespace) -> None:
    log.setup(3, log.filename("pf", args))

    try:
        args.func(args)
        exitcode = 0
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e!s}\n")
        exitcode = 2
    except Exception:
        traceback.print_exc()
        exitcode = 1

    sys.exit(exitcode)


def pf():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True, dest="command", metavar="command")

    register_parser = sub.add_parser("register", help="Register with bastions")
    register_parser.add_argument("--url", required=True, help="Bastion register URL")
    register_parser.add_argument("--hostname", default="hello", help="Target hostname")
    register_parser.add_argument("-p", "--port", type=int, default=2222, help="Local port to listen on")
    register_parser.add_argument("--socket-path", default=None, help="Path to a UNIX socket to connect to the bastion")
    register_parser.set_defaults(func=_register_function)

    connect_parser = sub.add_parser("connect", help="Connect via bastion")
    connect_parser.add_argument("--url", required=True, help="Bastion connect URL")
    connect_parser.add_argument("--hostname", default="hello", help="Target hostname")
    connect_parser.add_argument(
        "--socket-path", default=None, help="Path to a UNIX socket to connect to the bastion. Used only for testing"
    )
    connect_parser.set_defaults(func=_connect_function)

    args = parser.parse_args()

    _do_main(args)
