import argparse
import datetime
import json
import typing

import provablyfine_client as pfc
import tabulate

from ... import client


def _split_object(value: str) -> tuple[str, str]:
    object_type, separator, rest = value.partition(":")
    if not separator or not object_type or not rest:
        raise argparse.ArgumentTypeError(f"expected TYPE:VALUE, got {value!r}")
    return object_type, rest


def _fetch(sc: pfc.SessionClient, args: argparse.Namespace) -> tuple[list[pfc.schemas.AuditLogEntry], str | None]:
    """The entries to show, and the cursor of the next page if there is one."""
    filters: dict[str, typing.Any] = {
        "level": args.level,
        "object_type": args.object_type,
        "action": args.action,
        "by_identity_id": args.by_identity_id,
        "start_time": args.start_time,
        "end_time": args.end_time,
        "order": args.order,
    }
    ref_filters: list[dict[str, typing.Any]] = []
    if args.object is not None:
        object_type, name = args.object
        ref_filters.append({"ref_type": object_type, "ref_name": name})
        if args.follow:
            # The same object under another name: a rename keeps the id.
            for object_id in sc.find_object_ids(object_type, name):
                ref_filters.append({"ref_type": object_type, "ref_id": object_id})
    elif args.object_id is not None:
        object_type, object_id = args.object_id
        ref_filters.append({"ref_type": object_type, "ref_id": object_id})
    elif args.follow:
        raise pfc.exceptions.UI("--follow needs --object")

    if len(ref_filters) <= 1:
        extra = ref_filters[0] if ref_filters else {}
        if args.all:
            return list(sc.iter_audit_log(**filters, **extra)), None
        page = sc.list_audit_log(**filters, **extra, limit=args.limit, cursor=args.cursor)
        return page.entries, page.next_cursor

    # Several queries are merged. A cursor cannot span them, so the whole result is read.
    by_id: dict[int, pfc.schemas.AuditLogEntry] = {}
    for extra in ref_filters:
        for entry in sc.iter_audit_log(**filters, **extra):
            by_id[entry.id] = entry
    entries = sorted(by_id.values(), key=lambda e: e.id, reverse=args.order == "desc")
    return entries, None


def _list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    entries, next_cursor = _fetch(sc, args)
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(e.id) for e in entries)
        case "json":
            output = json.dumps([e.model_dump() for e in entries], indent=2)
        case "jsonl":
            output = "\n".join(json.dumps(e.model_dump()) for e in entries)
        case "text":
            rows: list[list[str | int]] = []
            for entry in entries:
                level_str = "WARN" if entry.level == 2 else "INFO"
                at_str = datetime.datetime.fromtimestamp(entry.at).isoformat()
                by = entry.by_identity_name or entry.by_identity_id or ""
                about = ", ".join(f"{r.type}:{r.name or r.id}" for r in entry.refs[:3])
                rows.append([entry.id, at_str, level_str, entry.type, by, about])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(
                    rows, headers=["id", "time", "level", "type", "by", "about"], maxcolwidths=80
                )
        case _:
            assert False
    if output:
        print(output)
    if next_cursor is not None and args.format == "text":
        print(f"More entries: --cursor {next_cursor}")


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    list_parser = subparsers.add_parser("list", help="List audit log entries, newest first")
    f = list_parser.add_argument_group("Filter criteria")
    f.add_argument("--level", type=int, choices=[1, 2], help="1=INFO 2=WARNING")
    f.add_argument(
        "--object-type",
        dest="object_type",
        action="append",
        help="Object type of the entry (e.g. role, identity). Repeat to allow several",
    )
    f.add_argument(
        "--action",
        action="append",
        help="Action of the entry (e.g. create, update-name, remove-members). Repeat to allow several",
    )
    f.add_argument(
        "--object",
        type=_split_object,
        metavar="TYPE:NAME",
        help="Entries about the object of this type that had this name, even if it is deleted now",
    )
    f.add_argument(
        "--object-id",
        dest="object_id",
        type=_split_object,
        metavar="TYPE:ID",
        help="Entries about the object of this type with this id",
    )
    f.add_argument(
        "--follow",
        action="store_true",
        default=False,
        help="With --object, also include the entries about the live object with this name, under its other names",
    )
    f.add_argument("--by", dest="by_identity_id", help="Identity ID of author")
    f.add_argument("--start-time", dest="start_time", type=int, help="Start Unix timestamp")
    f.add_argument("--end-time", dest="end_time", type=int, help="End Unix timestamp")
    p = list_parser.add_argument_group("Paging")
    p.add_argument("--order", choices=["asc", "desc"], default="desc", help="By entry id. Default: desc")
    p.add_argument("--limit", type=int, help="Entries per page. Server default: 100, maximum: 1000")
    p.add_argument("--cursor", help="Continue after the page that printed this cursor")
    p.add_argument("--all", action="store_true", default=False, help="Read every page")
    list_parser.add_argument("--format", choices=["text", "json", "jsonl", "quiet"], default="text")
    list_parser.add_argument("-q", "--quiet", action="store_true", default=False, help="Quiet output (IDs only)")
    list_parser.set_defaults(func=_list_function)
