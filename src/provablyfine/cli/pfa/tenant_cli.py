import argparse
import json

import tabulate

from ... import client


def _sort_by_id(t: client.schemas.Tenant) -> int:
    return t.id


def _sort_by_name(t: client.schemas.Tenant) -> tuple[str, int]:
    return (t.name, t.id)


def _list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    response = sc.list_tenants()
    tenants = response.tenants
    sort_functions = {
        "id": _sort_by_id,
        "name": _sort_by_name,
    }
    tenants = sorted(tenants, key=sort_functions[args.sort])
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(t.id) for t in tenants)
        case "json":
            output = json.dumps([t.model_dump() for t in tenants], indent=2)
        case "text":
            output = tabulate.tabulate([t.model_dump() for t in tenants], headers="keys") if tenants else ""
        case _:
            assert False
    if output:
        print(output)


def _get_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    t = sc.get_tenant(args.id)
    print(tabulate.tabulate([t.model_dump()], headers="keys"))


def _create_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    t = sc.create_tenant(name=args.name, display_name=args.display_name)
    print(tabulate.tabulate([t.model_dump()], headers="keys"))


def _update_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    is_enabled = None
    if args.enable:
        is_enabled = True
    elif args.disable:
        is_enabled = False
    sc.update_tenant(args.id, display_name=args.display_name, is_enabled=is_enabled)


def _delete_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.delete_tenant(args.id)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="_cmd2")

    list_parser = subparsers.add_parser("list", help="List tenants")
    list_parser.add_argument("-q", "--quiet", action="store_true", help="Equivalent to -f quiet")
    list_parser.add_argument(
        "-s", "--sort", choices=["id", "name"], default="id", help="Sort criterion. Default: %(default)s"
    )
    list_parser.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=_list_function)

    get_parser = subparsers.add_parser("get", help="Get a tenant")
    get_parser.add_argument("-i", "--id", type=int, required=True)
    get_parser.set_defaults(func=_get_function)

    create_parser = subparsers.add_parser("create", help="Create a tenant")
    create_parser.add_argument("--name", required=True, help="Tenant slug name")
    create_parser.add_argument("--display-name", required=True, dest="display_name", help="Tenant display name")
    create_parser.set_defaults(func=_create_function)

    update_parser = subparsers.add_parser("update", help="Update a tenant")
    update_parser.add_argument("-i", "--id", type=int, required=True)
    update_parser.add_argument("--display-name", dest="display_name", default=None)
    enable_group = update_parser.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", action="store_true", default=False)
    enable_group.add_argument("--disable", action="store_true", default=False)
    update_parser.set_defaults(func=_update_function)

    delete_parser = subparsers.add_parser("delete", help="Delete a tenant")
    delete_parser.add_argument("-i", "--id", type=int, required=True)
    delete_parser.set_defaults(func=_delete_function)
