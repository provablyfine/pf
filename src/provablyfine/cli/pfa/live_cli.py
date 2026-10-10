import argparse
import datetime
import json

import tabulate

from ... import client


def _time(at: int | None) -> str:
    return "" if at is None else datetime.datetime.fromtimestamp(at).isoformat()


def _list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    active: bool | None = True if args.active else False if args.ended else None
    sessions = sc.list_live(hostname=args.hostname, identity_id=args.identity_id, active=active).sessions
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(s.id for s in sessions)
        case "json":
            output = json.dumps([s.model_dump() for s in sessions], indent=2)
        case "text":
            rows = [
                [s.id, s.connection_id, s.hostname, s.identity_id, s.kind, _time(s.started_at), _time(s.ended_at)]
                for s in sessions
            ]
            headers = ["id", "connection", "host", "identity", "kind", "started", "ended"]
            output = tabulate.tabulate(rows, headers=headers) if rows else ""
        case _:
            assert False
    if output:
        print(output)


def _terminate_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.terminate_live(args.id)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    list_parser = subparsers.add_parser("list", help="List sessions seen by hosts and bastions")
    f = list_parser.add_argument_group("Filter criteria")
    f.add_argument("--hostname", help="Only sessions on this host")
    f.add_argument("--identity-id", dest="identity_id", type=int, help="Only sessions of this identity")
    state = f.add_mutually_exclusive_group()
    state.add_argument("--active", action="store_true", help="Only sessions that are still open")
    state.add_argument("--ended", action="store_true", help="Only sessions that ended")
    list_parser.add_argument("--format", choices=["text", "json", "quiet"], default="text")
    list_parser.add_argument(
        "-q", "--quiet", action="store_true", default=False, help="Quiet output (session ids only)"
    )
    list_parser.set_defaults(func=_list_function)

    terminate_parser = subparsers.add_parser("terminate", help="End a live session")
    terminate_parser.add_argument("id", help="Id of the session, as shown by list")
    terminate_parser.set_defaults(func=_terminate_function)
