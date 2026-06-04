import argparse
import json

import provablyfine_client as pfc
import tabulate

from ... import client


def _sort_by_id(t: pfc.schemas.Tag) -> int:
    return t.id


def _sort_by_name(t: pfc.schemas.Tag) -> tuple[str, str, int]:
    return (t.name, t.value, t.id)


def _sort_by_value(t: pfc.schemas.Tag) -> tuple[str, str, int]:
    return (t.value, t.name, t.id)


def tag_list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    response = sc.list_tags(id=args.id, name=args.name, value=args.value)
    tags = response.tags
    sort_functions = {
        "id": _sort_by_id,
        "name": _sort_by_name,
        "value": _sort_by_value,
    }
    tags = sorted(tags, key=sort_functions[args.sort])
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(t.id) for t in tags)
        case "json":
            output = json.dumps([t.model_dump() for t in tags], indent=2)
        case "text":
            rows: list[list[int | str]] = []
            for tag in tags:
                rows.append([tag.id, tag.name, tag.value])
            if rows:
                output = tabulate.tabulate(rows, headers=["id", "name", "value"])
            else:
                output = ""
        case _:
            assert False, args.format
    if output:
        print(output)


def _tag_create_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.create_tag(name=args.name, value=args.value)


def _tag_delete_function(args: argparse.Namespace) -> None:
    if args.id is None:
        raise pfc.exceptions.UI("You must specify a tag ID to delete")
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.delete_tag(id=args.id)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    list_parser = subparsers.add_parser("list", help="List tags we have access to")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-i", "--id", type=int, help="Id of tag.")
    group.add_argument("-n", "--name", type=str, help="Name of tag.")
    group.add_argument("-v", "--value", type=str, help="Value of tag.")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument(
        "-s", "--sort", choices=["id", "name", "value"], default="name", help="Sort criterion. Default: %(default)s"
    )
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=tag_list_function)

    create_parser = subparsers.add_parser("create", help="Create a new tag")
    create_parser.add_argument("-n", "--name", type=str, help="Name of tag.", required=True)
    create_parser.add_argument("-v", "--value", type=str, help="Value of tag.", required=True)
    create_parser.set_defaults(func=_tag_create_function)

    delete_parser = subparsers.add_parser("delete", help="Delete a tag")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of tag.")
    delete_parser.set_defaults(func=_tag_delete_function)
