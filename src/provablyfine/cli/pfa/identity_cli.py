import argparse
import json
import typing

import provablyfine_client as pfc
import tabulate

from ... import client


def _parse_tag(s: str) -> dict[str, str]:
    equal = s.find("=")
    if equal == -1:
        raise pfc.exceptions.UI(f"Tag is invalid. Expected format: name=value. Got: {s}")
    name = s[:equal]
    value = s[equal + 1 :]
    return {"name": name, "value": value}


def _format_tag_op(op: str, values: list[str]) -> list[pfc.schemas.IdentityTagOp]:
    tag_id_list = [int(t) for t in values if t.isdigit()]
    tag_name_value_list = [pfc.schemas.TagNameValue(**_parse_tag(t)) for t in values if not t.isdigit()]
    output: list[pfc.schemas.IdentityTagOp] = []
    if tag_id_list:
        output.append(pfc.schemas.IdentityTagOp(type=op, tag_id_list=tag_id_list))
    if tag_name_value_list:
        output.append(pfc.schemas.IdentityTagOp(type=op, tag_name_value_list=tag_name_value_list))
    return output


def _identity_list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    response = sc.list_identities(
        id=args.id,
        name=args.name,
        tag_id=args.tag_id,
        tag_name=args.tag_name,
        boundary_id=args.boundary_id,
        boundary_name=args.boundary_name,
    )
    identities = response.identities
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(i.id) for i in identities)
        case "json":
            output = json.dumps([i.model_dump() for i in identities], indent=2)
        case "text":
            rows: list[list[int | str]] = []
            for identity in identities:
                rows.append([identity.id, identity.name, len(identity.tags), len(identity.boundaries)])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(rows, headers=["id", "name", "ntags", "nboundaries"], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _identity_read_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    identity = sc.get_identity(args.id)
    match args.format:
        case "json":
            output = json.dumps(identity.model_dump(), indent=2)
        case "text":
            rows: list[tuple[str, int | str]] = []
            rows.append(("id", identity.id))
            rows.append(("name", identity.name))
            for t in identity.tags:
                rows.append(("tag", f"{t.name}={t.value}"))
            for b in identity.boundaries:
                rows.append(("boundary", b.name))
            output = tabulate.tabulate(rows, tablefmt="plain")
        case _:
            assert False
    print(output)


def _identity_delete_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.delete_identity(args.id)


def _identity_create_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    boundary_id_list = [int(b) for b in args.boundary if b.isdigit()]
    boundary_name_list = [b for b in args.boundary if not b.isdigit()]
    tag_id_list = [int(t) for t in args.tag if t.isdigit()]
    tag_name_value_list = [_parse_tag(t) for t in args.tag if not t.isdigit()]
    sc.create_identity(args.name, boundary_id_list, boundary_name_list, tag_id_list, tag_name_value_list)


def _identity_invite_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    key = sc.invite_identity(args.id, args.delivery)
    if key is not None:
        auth_name = args.auth or c.auth_name or "default"
        print(f"{c.directory_url}?invitation={key}&auth={auth_name}")


def _identity_update_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.update_identity(args.id, name=args.name)


class TagAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        items = getattr(namespace, self.dest, [])
        if items is None:
            items = []

        items.append((self.const, values))

        setattr(namespace, self.dest, items)


def _identity_tag_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()

    ops: list[pfc.schemas.IdentityTagOp] = []
    for op_type, values in args.ops:
        ops.extend(_format_tag_op(op_type, typing.cast(list[str], values or [])))

    sc.update_identity(args.id, tags=ops)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    list_parser = subparsers.add_parser("list", help="List identities we have access to")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-i", "--id", type=int, help="Id of identity")
    group.add_argument("-n", "--name", type=str, help="Name of identity")
    group.add_argument("--tag-id", type=str, help="Id of tag applied to identity", nargs="*")
    group.add_argument("--tag-name", type=str, help="Name of tag applied to identity", nargs="*")
    group.add_argument("--boundary-id", type=str, help="Id of boundary applied to identity", nargs="*")
    group.add_argument("--boundary-name", type=str, help="Name of boundary applied to identity", nargs="*")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument(
        "-s", "--sort", choices=["id", "name", "value"], default="name", help="Sort criterion. Default: %(default)s"
    )
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=_identity_list_function)

    read_parser = subparsers.add_parser("read", help="Show details on a specific identity")
    read_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    read_parser.add_argument("-f", "--format", choices=["json", "text"], default="text", help="Output format")
    read_parser.set_defaults(func=_identity_read_function)

    create_parser = subparsers.add_parser("create", help="Create a new identity")
    create_parser.add_argument("-n", "--name", type=str, help="Name of identity. Must be globally unique.")
    create_parser.add_argument(
        "-b", "--boundary", help="Boundary to enforce on newly-created identity", nargs="*", default=[]
    )
    create_parser.add_argument("-t", "--tag", help="Tag to apply on the newly-created identity", nargs="*", default=[])
    create_parser.set_defaults(func=_identity_create_function)

    invite_parser = subparsers.add_parser("invite", help="Invite an identity")
    invite_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    invite_parser.add_argument("--auth", default=None, help="Auth config name to include in invitation URL")
    group = invite_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--manual",
        action="store_const",
        const="manual",
        dest="delivery",
        help="Print the invitation. You are responsible for sharing this invitation securely with the user.",
    )
    group.add_argument(
        "--email", action="store_const", const="email", dest="delivery", help="Send the invitation by email"
    )
    invite_parser.set_defaults(func=_identity_invite_function)

    delete_parser = subparsers.add_parser("delete", help="Delete an unused identity")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    delete_parser.set_defaults(func=_identity_delete_function)

    update_parser = subparsers.add_parser("update", help="Update an existing identity")
    update_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    update_parser.add_argument("-n", "--name", help="New name of identity")
    update_parser.set_defaults(func=_identity_update_function)

    tag_parser = subparsers.add_parser(
        "tag", help="Update the list of tags assigned to an identity. Commands are processed in-order"
    )
    tag_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    tag_parser.add_argument(
        "-s", "--set", metavar="tag", dest="ops", const="set", help="Set list of tags", action=TagAction, nargs="*"
    )
    tag_parser.add_argument(
        "-a", "--add", metavar="tag", dest="ops", const="add", help="Add tag to identity", action=TagAction, nargs="*"
    )
    tag_parser.add_argument(
        "-d",
        "--del",
        metavar="tag",
        dest="ops",
        const="del",
        help="Delete tag from identity",
        action=TagAction,
        nargs="*",
    )
    tag_parser.set_defaults(func=_identity_tag_function)
