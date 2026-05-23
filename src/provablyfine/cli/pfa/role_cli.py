import argparse
import json
import typing

import tabulate

from ... import client
from .. import grant, yaml_utils


def _sort_by_id(t: client.schemas.Role) -> int:
    return t.id


def _sort_by_name(t: client.schemas.Role) -> tuple[str, int]:
    return (t.name, t.id)


def _role_list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    response = sc.list_roles(id=args.id, name=args.name)
    roles = response.roles
    sort_functions = {
        "id": _sort_by_id,
        "name": _sort_by_name,
    }
    roles = sorted(roles, key=sort_functions[args.sort])
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(r.id) for r in roles)
        case "json":
            output = json.dumps([r.model_dump() for r in roles], indent=2)
        case "yaml":
            output = yaml_utils.dump([r.model_dump() for r in roles])
        case "text":
            rows: list[list[int | str]] = []
            for role in roles:
                rows.append([role.id, role.name, role.description])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(rows, headers=["id", "name", "description"], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _role_read_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    role = sc.get_role(args.id)
    match args.format:
        case "json":
            output = json.dumps(role.model_dump(), indent=2)
        case "yaml":
            output = yaml_utils.dump(role.model_dump())
        case "text":
            rows: list[list[str | int]] = []
            rows.append(["id", role.id])
            rows.append(["name", role.name])
            rows.append(["description", role.description])
            for m in role.member_list:
                rows.append(["member", m.name])
            for g in role.grant_list:
                grant_text = g.to_text()
                rows.append(["grant", f"type:       {grant_text.type}"])
                rows.append(["", f"filter:     {grant_text.filter}"])
                rows.append(["", f"permission: {grant_text.permission}"])
            output = tabulate.tabulate(rows, tablefmt="plain")
        case _:
            assert False
    print(output)


def _role_delete_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.delete_role(args.id)


def _role_create_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.create_role(args.name, args.description or "")


def _role_update_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    sc.update_role(args.id, name=args.name, description=args.description)


def _role_grant_function(args: argparse.Namespace, action: str, grant: dict[str, typing.Any]) -> None:
    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    role = sc.get_role(args.id)

    match action:
        case "add":
            grant_list = [*role.grant_list, client.schemas.validate_grant(grant)]
        case "del":
            grant_list = [g for g in role.grant_list if g.model_dump() != grant]
        case "set":
            grant_list = [client.schemas.validate_grant(g) for g in grant]
        case _:
            assert False

    sc.update_role(role.id, grant_list=grant_list)


def _role_member_function(args: argparse.Namespace) -> None:

    def to_ref(member: str) -> client.schemas.RoleMemberRef:
        if member.isdigit():
            return client.schemas.RoleMemberRef(id=int(member))
        else:
            return client.schemas.RoleMemberRef(name=member)

    def is_equal(a: client.schemas.RoleMemberRef, b: client.schemas.RoleMemberRef) -> bool:
        if a.id is not None and b.id is not None and a.id == b.id:
            return True
        if a.name is not None and b.name is not None and a.name == b.name:
            return True
        return False

    c = client.Config.load(args.config)
    sc = client.sync.Client(c, timeout=args.timeout)
    role = sc.get_role(args.id)
    member_list: list[client.schemas.RoleMemberRef] = [
        client.schemas.RoleMemberRef(id=m.id, name=m.name) for m in role.member_list
    ]

    for added in args.add:
        member = to_ref(added)
        if not any(is_equal(member, m) for m in member_list):
            member_list.append(member)

    for deleted in args.delete:
        member = to_ref(deleted)
        member_list = [m for m in member_list if not is_equal(m, member)]

    if args.set is not None:
        member_list = [to_ref(m) for m in args.set]

    sc.update_role(role.id, member_list=member_list)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    list_parser = subparsers.add_parser("list", help="List roles we have access to")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-n", "--name", type=str, help="Name of role.")
    group.add_argument("-i", "--id", type=int, help="Id of role.")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument(
        "-s", "--sort", choices=["id", "name"], default="name", help="Sort criterion. Default: %(default)s"
    )
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument(
        "-f", "--format", choices=["json", "yaml", "text", "quiet"], default="text", help="Output format"
    )
    list_parser.set_defaults(func=_role_list_function)

    read_parser = subparsers.add_parser("read", help="Show details on a specific role")
    read_parser.add_argument("-i", "--id", type=int, help="Id of role.", required=True)
    read_parser.add_argument("-f", "--format", choices=["json", "yaml", "text"], default="text", help="Output format")
    read_parser.set_defaults(func=_role_read_function)

    create_parser = subparsers.add_parser("create", help="Create a new role")
    create_parser.add_argument("-n", "--name", type=str, help="Name of role. Must be globally unique.", required=True)
    create_parser.add_argument("-d", "--description", type=str, help="Description")
    create_parser.set_defaults(func=_role_create_function)

    delete_parser = subparsers.add_parser("delete", help="Delete an unused role")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of role.", required=True)
    delete_parser.set_defaults(func=_role_delete_function)

    update_parser = subparsers.add_parser("update", help="Update a role")
    update_parser.add_argument("-i", "--id", type=int, help="Id of role.", required=True)
    update_parser.add_argument("-n", "--name", type=str, help="Name")
    update_parser.add_argument("-d", "--description", type=str, help="Description")
    update_parser.set_defaults(func=_role_update_function)

    grant_parser = subparsers.add_parser("grant", help="Update the list of grants granted by role")
    grant_parser.add_argument("-i", "--id", type=int, help="Id of role.", required=True)
    grant.add_parser(grant_parser, _role_grant_function)

    members_parser = subparsers.add_parser("member", help="Update the list of members assigned to this role")
    members_parser.add_argument("-i", "--id", type=int, help="Id of role.", required=True)
    members_parser.add_argument("-a", "--add", type=str, help="Add member to role", nargs="*", default=[])
    members_parser.add_argument(
        "-d", "--del", dest="delete", type=str, help="Delete member from role", nargs="*", default=[]
    )
    members_parser.add_argument("-s", "--set", type=str, help="Set member list", nargs="*", default=None)
    members_parser.set_defaults(func=_role_member_function)
