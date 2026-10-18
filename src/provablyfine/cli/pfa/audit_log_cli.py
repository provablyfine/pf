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


def _fetch(
    sc: pfc.SessionClient, args: argparse.Namespace
) -> tuple[list[pfc.schemas.AuditLogEntry], pfc.schemas.AuditLogListResponse]:
    """The entries to show, and the last page that was read. Its cursor is where to continue from."""
    filters: dict[str, typing.Any] = {
        "level": args.level,
        "object_type": args.object_type,
        "action": args.action,
        "by_identity_id": args.by_identity_id,
        "start_time": args.start_time,
        "end_time": args.end_time,
        "order": args.order,
    }
    if args.object is not None:
        object_type, name = args.object
        filters.update(ref_type=object_type, ref_name=name, ref_follow=args.follow)
    elif args.object_id is not None:
        if args.follow:
            raise pfc.exceptions.UI("--follow needs --object. An object id already follows the object through renames")
        object_type, object_id = args.object_id
        filters.update(ref_type=object_type, ref_id=object_id)
    elif args.follow:
        raise pfc.exceptions.UI("--follow needs --object")

    page = sc.list_audit_log(**filters, limit=args.limit, cursor=args.cursor)
    entries = list(page.entries)
    while args.all and not page.is_last:
        page = sc.list_audit_log(**filters, limit=args.limit, cursor=page.next_cursor)
        entries.extend(page.entries)
    return entries, page


def _list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    entries, page = _fetch(sc, args)
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(e.id) for e in entries)
        case "json":
            output = json.dumps(
                {
                    "entries": [e.model_dump() for e in entries],
                    "next_cursor": page.next_cursor,
                    "is_last": page.is_last,
                },
                indent=2,
            )
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
    if not page.is_last and args.format == "text":
        print(f"More entries: --cursor {page.next_cursor}")


def _types_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    object_types = sc.list_audit_log_types().object_types
    match args.format:
        case "json":
            print(json.dumps([t.model_dump() for t in object_types], indent=2))
        case "text":
            rows = [[t.object_type, " ".join(t.actions)] for t in object_types]
            print(tabulate.tabulate(rows, headers=["object type", "actions"], maxcolwidths=80))
        case _:
            assert False


def _objects_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    object_type, name = args.object
    response = sc.list_audit_log_objects(object_type, name, order=args.order, limit=args.limit, cursor=args.cursor)
    objects = list(response.objects)
    while args.all and not response.is_last:
        response = sc.list_audit_log_objects(
            object_type, name, order=args.order, limit=args.limit, cursor=response.next_cursor
        )
        objects.extend(response.objects)
    match args.format:
        case "json":
            print(
                json.dumps(
                    {
                        "objects": [o.model_dump() for o in objects],
                        "next_cursor": response.next_cursor,
                        "is_last": response.is_last,
                    },
                    indent=2,
                )
            )
        case "text":
            rows = [
                [
                    o.type,
                    o.id,
                    ", ".join(o.names),
                    datetime.datetime.fromtimestamp(o.first_seen).isoformat(),
                    datetime.datetime.fromtimestamp(o.last_seen).isoformat(),
                ]
                for o in objects
            ]
            if rows:
                print(
                    tabulate.tabulate(rows, headers=["type", "id", "names", "first seen", "last seen"], maxcolwidths=60)
                )
            if not response.is_last:
                print(f"More objects: --cursor {response.next_cursor}")
        case _:
            assert False


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    list_parser = subparsers.add_parser(
        "list",
        help="List audit log entries, newest first",
        description="List audit log entries, newest first. Run 'pfa audit-log types' for the values of "
        "--object-type and --action.",
        epilog="examples:\n"
        "  pfa audit-log list --object-type role --action update-grant-list\n"
        "  pfa audit-log list --object role:admin --follow\n"
        "  pfa audit-log list --level 2 --start-time 1700000000 --all",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    f = list_parser.add_argument_group("Filter criteria")
    f.add_argument("--level", type=int, choices=[1, 2], help="1=INFO 2=WARNING")
    f.add_argument(
        "--object-type",
        dest="object_type",
        action="append",
        help="Object type of the entry (e.g. role, identity). Repeat to allow several. See 'pfa audit-log types'",
    )
    f.add_argument(
        "--action",
        action="append",
        help="Action of the entry (e.g. create, update-name, remove-members). Repeat to allow several. "
        "See 'pfa audit-log types'",
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
        help="With --object, also include the entries about every object that ever had this name, "
        "under all the names it had, even if it is deleted now",
    )
    f.add_argument("--by", dest="by_identity_id", help="Identity ID of author")
    f.add_argument("--start-time", dest="start_time", type=int, help="Start Unix timestamp")
    f.add_argument("--end-time", dest="end_time", type=int, help="End Unix timestamp")
    p = list_parser.add_argument_group("Paging")
    p.add_argument("--order", choices=["asc", "desc"], default="desc", help="By entry id. Default: desc")
    p.add_argument("--limit", type=int, help="Entries per page. Server default: 100, maximum: 1000")
    p.add_argument("--cursor", help="Continue after the page that printed this cursor")
    p.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="Read every page, from the start or from --cursor. --limit is the page size",
    )
    list_parser.add_argument(
        "--format",
        choices=["text", "json", "quiet"],
        default="text",
        help="json is an object with entries, next_cursor and is_last. Pass next_cursor to --cursor to continue. "
        "quiet prints the entry ids only and cannot be continued",
    )
    list_parser.add_argument("-q", "--quiet", action="store_true", default=False, help="Quiet output (IDs only)")
    list_parser.set_defaults(func=_list_function)

    types_parser = subparsers.add_parser("types", help="List the object types and actions of audit log entries")
    types_parser.add_argument("--format", choices=["text", "json"], default="text")
    types_parser.set_defaults(func=_types_function)

    objects_parser = subparsers.add_parser(
        "objects",
        help="List the objects that ever had a name, to find the id to give to --object-id",
        description="List the objects that ever had a name, newest first, even if they were renamed or deleted. "
        "Each one is shown with all the names it had. Give its id to 'pfa audit-log list --object-id TYPE:ID'.",
    )
    objects_parser.add_argument(
        "--object", type=_split_object, required=True, metavar="TYPE:NAME", help="For example role:ops"
    )
    objects_parser.add_argument(
        "--order", choices=["asc", "desc"], default="desc", help="By when the object first got the name. Default: desc"
    )
    objects_parser.add_argument("--limit", type=int, help="Objects per page. Server default: 100, maximum: 1000")
    objects_parser.add_argument("--cursor", help="Continue after the page that printed this cursor")
    objects_parser.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="Read every page, from the start or from --cursor. --limit is the page size",
    )
    objects_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="json is an object with objects, next_cursor and is_last",
    )
    objects_parser.set_defaults(func=_objects_function)
