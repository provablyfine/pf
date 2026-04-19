import argparse
import datetime
import json

import tabulate

from ... import client


def _list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    response = sc.list_audit_log(
        level=args.level,
        object_type=args.object_type,
        by_identity_id=args.by_identity_id,
        start_time=args.start_time,
        end_time=args.end_time,
    )
    entries = response.entries
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(e.id) for e in entries)
        case "json":
            output = json.dumps([e.model_dump() for e in entries], indent=2)
        case "text":
            rows: list[list[str | int]] = []
            for entry in entries:
                level_str = "WARN" if entry.level == 2 else "INFO"
                at_str = datetime.datetime.fromtimestamp(entry.at).isoformat()
                rows.append([entry.id, at_str, level_str, entry.type, entry.by_identity_id or ""])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(rows, headers=["id", "time", "level", "type", "by"], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="_cmd2")

    list_parser = subparsers.add_parser("list", help="List audit log entries")
    f = list_parser.add_argument_group("Filter criteria")
    f.add_argument("--level", type=int, choices=[1, 2], help="1=INFO 2=WARNING")
    f.add_argument("--object-type", dest="object_type", help="Object type prefix (e.g. bastion, identity)")
    f.add_argument("--by", dest="by_identity_id", help="Identity ID of author")
    f.add_argument("--start-time", dest="start_time", type=int, help="Start Unix timestamp")
    f.add_argument("--end-time", dest="end_time", type=int, help="End Unix timestamp")
    list_parser.add_argument("--format", choices=["text", "json", "quiet"], default="text")
    list_parser.add_argument("-q", "--quiet", action="store_true", default=False, help="Quiet output (IDs only)")
    list_parser.set_defaults(func=_list_function)
