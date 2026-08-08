import argparse
import json

import provablyfine_client as pfc

from .. import yaml_utils


def _output(args: argparse.Namespace, data: object) -> None:
    match args.format:
        case "yaml":
            output = yaml_utils.dump(data)
        case "json":
            output = json.dumps(data, indent=2)
        case _:
            assert False
    print(output)


def _tag(t: str) -> dict[str, str]:
    equal = t.find("=")
    if equal == -1:
        raise pfc.exceptions.UI(f"Tag is invalid. Expected name=value. Got: {t}")
    name = t[:equal]
    value = t[equal + 1 :]
    return {"name": name, "value": value}


def _tag_list(tags: list[str] | None) -> list[dict[str, str]] | None:
    if tags is None:
        return None
    return [_tag(t) for t in tags]


def _all_or(is_all: bool, default: object) -> object | None:
    if is_all:
        return None
    return default


def _tag_function(args: argparse.Namespace) -> None:
    tag = {
        "type": "tag",
        "filter": {"name_value": None if args.name_value is None else _tag(args.name_value)},
        "permission": {
            "create": args.create,
            "read": args.read,
            "delete": args.delete,
        },
    }
    _output(args, tag)


def _role_function(args: argparse.Namespace) -> None:
    role = {
        "type": "role",
        "filter": {"name": args.name},
        "permission": {
            "create": args.create,
            "read": args.read,
            "update": _all_or(
                args.update_all,
                {
                    "name": any("name" in entry for entry in args.update),
                    "description": any("description" in entry for entry in args.update),
                    "grant_list": any("grant_list" in entry for entry in args.update),
                    "member_list": any("member_list" in entry for entry in args.update),
                },
            ),
            "delete": args.delete,
        },
    }
    _output(args, role)


def _boundary_function(args: argparse.Namespace) -> None:
    boundary = {
        "type": "boundary",
        "filter": {"name": args.name},
        "permission": {
            "create": args.create,
            "read": args.read,
            "update": _all_or(
                args.update_all,
                {
                    "name": any("name" in entry for entry in args.update),
                    "description": any("description" in entry for entry in args.update),
                    "denied_list": any("denied_list" in entry for entry in args.update),
                    "ceiling_list": any("ceiling_list" in entry for entry in args.update),
                },
            ),
            "delete": args.delete,
        },
    }
    _output(args, boundary)


def _tenant_function(args: argparse.Namespace) -> None:
    tenant = {
        "type": "tenant",
        "filter": {"id": args.id},
        "permission": {
            "create": args.create,
            "read": args.read,
            "delete": args.delete,
            "update": _all_or(
                args.update_all,
                {
                    "display_name": any("display_name" in entry for entry in args.update),
                    "is_enabled": any("is_enabled" in entry for entry in args.update),
                },
            ),
        },
    }
    _output(args, tenant)


def _bastion_function(args: argparse.Namespace) -> None:
    bastion = {
        "type": "bastion",
        "filter": {"id": args.id},
        "permission": {
            "create": args.create,
            "read": args.read,
            "delete": args.delete,
            "update": _all_or(
                args.update_all,
                {
                    "url": any("url" in entry for entry in args.update),
                    "ssh_proxy_jump": any("ssh_proxy_jump" in entry for entry in args.update),
                    "tag_list": any("tag_list" in entry for entry in args.update),
                },
            ),
        },
    }
    _output(args, bastion)


def _identity_function(args: argparse.Namespace) -> None:
    identity = {
        "type": "identity",
        "filter": {
            "name": args.name,
            "tag_list": _tag_list(args.tag),
            "boundary_list": args.boundary,
        },
        "permission": {
            "create": {
                "allowed": args.create_allowed,
                "allowed_tag_list": _tag_list(args.create_allowed_tag),
                "required_boundary_list": args.create_required_boundary,
            },
            "read": args.read,
            "update": _all_or(
                args.update_all,
                {
                    "name": any("name" in entry for entry in args.update),
                    "unix_username": any("unix_username" in entry for entry in args.update),
                },
            ),
            "delete": args.delete,
            "add_tag_list": _all_or(args.add_tag_all, [_tag(t) for t in args.add_tag]),
            "del_tag_list": _all_or(args.del_tag_all, [_tag(t) for t in args.del_tag]),
            "invite_list": args.invite,
        },
    }
    _output(args, identity)


def _ssh_function(args: argparse.Namespace) -> None:
    # The schema permits an empty list on any axis, so that upcast stays total
    # over legacy rows. An authoring surface should still refuse to write a
    # grant that covers nothing.
    username_list = _all_or(args.username_all, args.username)
    capability_list = _all_or(args.capability_all, args.capability)
    command_list = _all_or(args.cmd_all, args.cmd)
    if username_list == []:
        raise pfc.exceptions.UI("Grant has no username. Pass --username or --username-all.")
    if capability_list == [] and command_list == []:
        raise pfc.exceptions.UI("Grant is empty. Pass --capability, --cmd, or one of their --*-all forms.")
    grant = {
        "type": "ssh",
        "filter": {
            "name": args.name,
            "tag_list": _tag_list(args.tag),
            "boundary_list": args.boundary,
        },
        "permission": {
            "username_list": username_list,
            "capability_list": capability_list,
            "command_list": command_list,
        },
    }
    _output(args, grant)


def _audit_log_function(args: argparse.Namespace) -> None:
    grant = {
        "type": "audit-log",
        "filter": {},
        "permission": {
            "read": args.read,
        },
    }
    _output(args, grant)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    tag_parser = subparsers.add_parser("tag", help="Tag permission")
    tag_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = tag_parser.add_argument_group("filter")
    group.add_argument("--name-value", default=None)
    group = tag_parser.add_argument_group("permission")
    group.add_argument("-c", "--create", action="store_true")
    group.add_argument("-r", "--read", action="store_true")
    group.add_argument("-d", "--delete", action="store_true")
    tag_parser.set_defaults(func=_tag_function)

    role_parser = subparsers.add_parser("role", help="Role permission")
    role_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = role_parser.add_argument_group("filter")
    group.add_argument("--name", default=None)
    group = role_parser.add_argument_group("permission")
    group.add_argument("-c", "--create", action="store_true")
    group.add_argument("-r", "--read", action="store_true")
    group.add_argument(
        "-u",
        "--update",
        action="append",
        nargs="*",
        default=[],
        choices=["name", "description", "member_list", "grant_list"],
    )
    group.add_argument("--update-all", action="store_true")
    group.add_argument("-d", "--delete", action="store_true")
    role_parser.set_defaults(func=_role_function)

    boundary_parser = subparsers.add_parser("boundary", help="Boundary permission")
    boundary_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = boundary_parser.add_argument_group("filter")
    group.add_argument("--name", default=None)
    group = boundary_parser.add_argument_group("permission")
    group.add_argument("-c", "--create", action="store_true")
    group.add_argument("-r", "--read", action="store_true")
    group.add_argument(
        "-u",
        "--update",
        action="append",
        nargs="*",
        default=[],
        choices=["name", "description", "denied_list", "ceiling_list"],
    )
    group.add_argument("--update-all", action="store_true")
    group.add_argument("-d", "--delete", action="store_true")
    boundary_parser.set_defaults(func=_boundary_function)

    tenant_parser = subparsers.add_parser("tenant", help="Tenant permission")
    tenant_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = tenant_parser.add_argument_group("filter")
    group.add_argument("--id", type=int, default=None)
    group = tenant_parser.add_argument_group("permission")
    group.add_argument("-c", "--create", action="store_true")
    group.add_argument("-r", "--read", action="store_true")
    group.add_argument(
        "-u",
        "--update",
        action="append",
        nargs="*",
        default=[],
        choices=["display_name", "is_enabled"],
    )
    group.add_argument("--update-all", action="store_true")
    group.add_argument("-d", "--delete", action="store_true")
    tenant_parser.set_defaults(func=_tenant_function)

    bastion_parser = subparsers.add_parser("bastion", help="Bastion permission")
    bastion_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = bastion_parser.add_argument_group("filter")
    group.add_argument("--id", type=int, default=None)
    group = bastion_parser.add_argument_group("permission")
    group.add_argument("-c", "--create", action="store_true")
    group.add_argument("-r", "--read", action="store_true")
    group.add_argument(
        "-u",
        "--update",
        action="append",
        nargs="*",
        default=[],
        choices=["url", "ssh_proxy_jump", "tag_list"],
    )
    group.add_argument("--update-all", action="store_true")
    group.add_argument("-d", "--delete", action="store_true")
    bastion_parser.set_defaults(func=_bastion_function)

    identity_parser = subparsers.add_parser("identity", help="Identity permission")
    identity_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = identity_parser.add_argument_group("filter")
    group.add_argument("--name", default=None)
    group.add_argument("--tag", default=None, nargs="*")
    group.add_argument("--boundary", default=None, nargs="*")
    group = identity_parser.add_argument_group("permission")
    group.add_argument("--create-allowed", action="store_true")
    group.add_argument("--create-allowed-tag", default=None, nargs="*")
    group.add_argument("--create-required-boundary", default=None, nargs="*")
    group.add_argument("-r", "--read", action="store_true")
    group.add_argument("--update-all", action="store_true")
    group.add_argument(
        "-u",
        "--update",
        action="append",
        nargs="*",
        default=[],
        choices=["name", "unix_username"],
    )
    group.add_argument("-d", "--delete", action="store_true")
    group.add_argument("--add-tag", default=[], nargs="*")
    group.add_argument("--add-tag-all", action="store_true")
    group.add_argument("--del-tag", default=[], nargs="*")
    group.add_argument("--del-tag-all", action="store_true")
    group.add_argument("--invite", default=[], nargs="*", choices=["email", "manual"])
    identity_parser.set_defaults(func=_identity_function)

    ssh_parser = subparsers.add_parser("ssh", help="SSH permission")
    ssh_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = ssh_parser.add_argument_group("filter")
    group.add_argument("--name", default=None)
    group.add_argument("--tag", default=None, nargs="*")
    group.add_argument("--boundary", default=None, nargs="*")
    group = ssh_parser.add_argument_group("permission")
    group.add_argument("--username", nargs="*", default=[])
    group.add_argument("--username-all", action="store_true", help="Any username")
    group.add_argument("--capability", nargs="*", default=[], choices=[c.value for c in pfc.schemas.SSHCapability])
    group.add_argument("--capability-all", action="store_true", help="Every capability, present and future")
    group.add_argument("--cmd", nargs="*", default=[])
    group.add_argument("--cmd-all", action="store_true", help="Any command")
    ssh_parser.set_defaults(func=_ssh_function)

    audit_log_parser = subparsers.add_parser("audit-log", help="Audit log permission")
    audit_log_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = audit_log_parser.add_argument_group("permission")
    group.add_argument("-r", "--read", action="store_true")
    audit_log_parser.set_defaults(func=_audit_log_function)
