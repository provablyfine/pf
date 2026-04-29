import argparse
import json

import tabulate

from ... import client


def _parse_tag(s: str) -> dict[str, str]:
    equal = s.find("=")
    if equal == -1:
        raise client.exceptions.UI(f"Tag is invalid. Expected format: name=value. Got: {s}")
    name = s[:equal]
    value = s[equal + 1 :]
    return {"name": name, "value": value}


def _bastion_list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    response = sc.list_bastions(id=args.id)
    bastions = response.bastions
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(b.id) for b in bastions)
        case "json":
            output = json.dumps([b.model_dump() for b in bastions], indent=2)
        case "text":
            rows: list[list[int | str]] = []
            for bastion in bastions:
                rows.append([bastion.id, bastion.url, len(bastion.tag_list)])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(rows, headers=["id", "url", "ntags"], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _bastion_read_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    bastion = sc.get_bastion(args.id)
    match args.format:
        case "json":
            output = json.dumps(bastion.model_dump(), indent=2)
        case "text":
            rows: list[list[int | str]] = []
            rows.append(["id", bastion.id])
            rows.append(["url", bastion.url])
            if bastion.ssh_proxy_jump:
                rows.append(["ssh_proxy_jump", bastion.ssh_proxy_jump])
            for tag in bastion.tag_list:
                rows.append(["tag", f"{tag.name}={tag.value}"])
            output = tabulate.tabulate(rows, tablefmt="plain")
        case _:
            assert False
    print(output)


def _bastion_delete_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.delete_bastion(args.id)


def _bastion_create_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    tag_id_list = [int(t) for t in args.tag if t.isdigit()]
    tag_name_value_list = [_parse_tag(t) for t in args.tag if not t.isdigit()]
    sc.create_bastion(args.url, args.ssh_proxy_jump, tag_id_list, tag_name_value_list)


def _bastion_update_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.update_bastion(args.id, args.url, args.ssh_proxy_jump)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="_cmd2")

    list_parser = subparsers.add_parser("list", help="List bastions")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-i", "--id", type=int, help="Id of bastion")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=_bastion_list_function)

    read_parser = subparsers.add_parser("read", help="Show details on a specific bastion")
    read_parser.add_argument("-i", "--id", type=int, help="Id of bastion", required=True)
    read_parser.add_argument("-f", "--format", choices=["json", "text"], default="text", help="Output format")
    read_parser.set_defaults(func=_bastion_read_function)

    create_parser = subparsers.add_parser("create", help="Create a new bastion")
    create_parser.add_argument("--register-url", type=str, required=True, help="Register URL of the bastion")
    create_parser.add_argument("--connect-url", type=str, help="Connect URL of the bastion")
    create_parser.add_argument("--ssh-proxy-jump", type=str, help="SSH ProxyJump string")
    create_parser.add_argument("-t", "--tag", help="Tag to apply on the bastion", nargs="*", default=[])
    create_parser.set_defaults(func=_bastion_create_function)

    delete_parser = subparsers.add_parser("delete", help="Delete a bastion")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of bastion", required=True)
    delete_parser.set_defaults(func=_bastion_delete_function)

    update_parser = subparsers.add_parser("update", help="Update a bastion")
    update_parser.add_argument("-i", "--id", type=int, help="Id of bastion", required=True)
    update_parser.add_argument("--register-url", type=str, help="Register URL of the bastion")
    update_parser.add_argument("--connect-url", type=str, help="Connect URL of the bastion")
    update_parser.add_argument("--ssh-proxy-jump", type=str, help="SSH ProxyJump string")
    update_parser.set_defaults(func=_bastion_update_function)
