import argparse
import json
import typing

import tabulate

from ... import client
from .. import grant, yaml_utils


def _sort_by_id(b: client.schemas.Boundary) -> int:
    return b.id


def _sort_by_name(b: client.schemas.Boundary) -> tuple[str, int]:
    return (b.name, b.id)


def _boundary_list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    response = sc.list_boundaries(id=args.id, name=args.name)
    boundaries = response.boundaries
    sort_functions = {
        "id": _sort_by_id,
        "name": _sort_by_name,
    }
    boundaries = sorted(boundaries, key=sort_functions[args.sort])
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(b.id) for b in boundaries)
        case "json":
            output = json.dumps([b.model_dump() for b in boundaries], indent=2)
        case "yaml":
            output = yaml_utils.dump([b.model_dump() for b in boundaries])
        case "text":
            rows: list[list[int | str]] = []
            for boundary in boundaries:
                rows.append([boundary.id, boundary.name, boundary.description])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(rows, headers=["id", "name", "description"], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _boundary_read_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    boundary = sc.get_boundary(args.id)
    match args.format:
        case "json":
            output = json.dumps(boundary.model_dump(), indent=2)
        case "yaml":
            output = yaml_utils.dump(boundary.model_dump())
        case "text":
            rows: list[list[str | int]] = []
            rows.append(["id", boundary.id])
            rows.append(["name", boundary.name])
            rows.append(["description", boundary.description])
            if boundary.ceiling_list is None:
                rows.append(["ceiling", "*"])
            elif len(boundary.ceiling_list) == 0:
                rows.append(["ceiling", "[]"])
            else:
                for g in boundary.ceiling_list:
                    grant_text = g.to_text()
                    rows.append(["ceiling", f"type:       {grant_text.type}"])
                    rows.append(["", f"filter:     {grant_text.filter}"])
                    rows.append(["", f"permission: {grant_text.permission}"])
            for g in boundary.denied_list:
                grant_text = g.to_text()
                rows.append(["denied", f"type:       {grant_text.type}"])
                rows.append(["", f"filter:     {grant_text.filter}"])
                rows.append(["", f"permission: {grant_text.permission}"])
            output = tabulate.tabulate(rows, tablefmt="plain")
        case _:
            assert False
    print(output)


def _boundary_delete_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.delete_boundary(args.id)


def _boundary_create_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.create_boundary(args.name, args.description or "")


def _boundary_update_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.update_boundary(args.id, name=args.name, description=args.description)


def _boundary_grant_function(
    args: argparse.Namespace, action: str, grant: dict[str, typing.Any] | list[typing.Any], field_name: str
) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    boundary = sc.get_boundary(args.id)

    current_list = getattr(boundary, field_name)

    match action:
        case "add":
            grant_obj = client.schemas.validate_grant(grant)
            grant_list = [grant_obj] if current_list is None else [*current_list, grant_obj]
        case "del":
            grant_obj = client.schemas.validate_grant(grant)
            if current_list is None:
                grant_list = None
            else:
                grant_list = [g for g in current_list if g.model_dump() != grant]
        case "set":
            grant_list = [client.schemas.validate_grant(g) for g in grant]
        case _:
            assert False

    if field_name == "ceiling_list":
        sc.update_boundary(boundary.id, ceiling_list=grant_list)
    else:  # denied_list
        sc.update_boundary(boundary.id, denied_list=grant_list)


def _boundary_denied_function(args: argparse.Namespace, action: str, grant: dict[str, typing.Any]) -> None:
    _boundary_grant_function(args, action, grant, "denied_list")


def _boundary_ceiling_function(args: argparse.Namespace, action: str, grant: dict[str, typing.Any]) -> None:
    _boundary_grant_function(args, action, grant, "ceiling_list")


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="_cmd2")

    list_parser = subparsers.add_parser("list", help="List boundaries we have access to")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-n", "--name", type=str, help="Name of boundary.")
    group.add_argument("-i", "--id", type=int, help="Id of boundary.")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument(
        "-s", "--sort", choices=["id", "name"], default="name", help="Sort criterion. Default: %(default)s"
    )
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=_boundary_list_function)

    read_parser = subparsers.add_parser("read", help="Show details on a specific boundary")
    read_parser.add_argument("-i", "--id", type=int, help="Id of boundary.", required=True)
    read_parser.add_argument("-f", "--format", choices=["json", "yaml", "text"], default="text", help="Output format")
    read_parser.set_defaults(func=_boundary_read_function)

    create_parser = subparsers.add_parser("create", help="Create a new boundary")
    create_parser.add_argument(
        "-n", "--name", type=str, help="Name of boundary. Must be globally unique.", required=True
    )
    create_parser.add_argument("-d", "--description", type=str, help="Description")
    create_parser.set_defaults(func=_boundary_create_function)

    update_parser = subparsers.add_parser("update", help="Update description")
    update_parser.add_argument("-i", "--id", type=int, help="Id of boundary.", required=True)
    update_parser.add_argument("-n", "--name", type=str, help="Name")
    update_parser.add_argument("-d", "--description", type=str, help="Description")
    update_parser.set_defaults(func=_boundary_update_function)

    denied_parser = subparsers.add_parser("denied", help="Update the list of denied grants for boundary")
    denied_parser.add_argument("-i", "--id", type=int, help="Id of boundary.", required=True)
    grant.add_parser(denied_parser, _boundary_denied_function)

    ceiling_parser = subparsers.add_parser("ceiling", help="Update the list of celling permissions for boundary")
    ceiling_parser.add_argument("-i", "--id", type=int, help="Id of boundary.", required=True)
    grant.add_parser(ceiling_parser, _boundary_ceiling_function)

    delete_parser = subparsers.add_parser("delete", help="Delete an unused boundary")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of boundary.", required=True)
    delete_parser.set_defaults(func=_boundary_delete_function)
