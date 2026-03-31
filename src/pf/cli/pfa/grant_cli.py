import json

from ... import client
from .. import yaml_utils


def _output(args, data):
    match args.format:
        case "yaml":
            output = yaml_utils.dump(data)
        case "json":
            output = json.dumps(data, indent=2)
        case _:
            assert False
    print(output)


def _tag(t):
    equal = t.find("=")
    if equal == -1:
        raise client.exceptions.UI(f"Tag is invalid. Expected name=value. Got: {t}")
    name = t[:equal]
    value = t[equal + 1 :]
    return {"name": name, "value": value}


def _tag_list(tags):
    if tags is None:
        return None
    return [_tag(t) for t in tags]


def _all_or(is_all, default):
    if is_all:
        return None
    return default


def _tag_function(args):
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


def _role_function(args):
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


def _boundary_function(args):
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


def _identity_function(args):
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
                },
            ),
            "delete": args.delete,
            "add_tag_list": _all_or(args.add_tag_all, [_tag(t) for t in args.add_tag]),
            "del_tag_list": _all_or(args.del_tag_all, [_tag(t) for t in args.del_tag]),
            "invite_list": args.invite,
        },
    }
    _output(args, identity)


def _ssh_shell_function(args):
    grant = {
        "type": "ssh-shell",
        "filter": {
            "name": args.name,
            "tag_list": _tag_list(args.tag),
            "boundary_list": args.boundary,
        },
        "permission": {
            "username_list": args.username,
            "permit_agent_forwarding": args.permit_agent_forwarding,
            "permit_x11_forwarding": args.permit_x11_forwarding,
        },
    }
    _output(args, grant)


def _ssh_port_forwarding_function(args):
    grant = {
        "type": "ssh-port-forwarding",
        "filter": {
            "name": args.name,
            "tag_list": _tag_list(args.tag),
            "boundary_list": args.boundary,
        },
        "permission": {
            "username_list": args.username,
        },
    }
    _output(args, grant)


def _ssh_command_function(args):
    grant = {
        "type": "ssh-command",
        "filter": {
            "name": args.name,
            "tag_list": _tag_list(args.tag),
            "boundary_list": args.boundary,
        },
        "permission": {
            "username_list": args.username,
            "command_list": args.command,
        },
    }
    _output(args, grant)


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    tag_parser = subparsers.add_parser("tag")
    tag_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = tag_parser.add_argument_group("filter")
    group.add_argument("--name-value", default=None)
    group = tag_parser.add_argument_group("permission")
    group.add_argument("-c", "--create", action="store_true")
    group.add_argument("-r", "--read", action="store_true")
    group.add_argument("-d", "--delete", action="store_true")
    tag_parser.set_defaults(func=_tag_function)

    role_parser = subparsers.add_parser("role")
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

    boundary_parser = subparsers.add_parser("boundary")
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

    identity_parser = subparsers.add_parser("identity")
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
    group.add_argument("-u", "--update", action="append", nargs="*", default=[], choices=["name"])
    group.add_argument("-d", "--delete", action="store_true")
    group.add_argument("--add-tag", default=[], nargs="*")
    group.add_argument("--add-tag-all", action="store_true")
    group.add_argument("--del-tag", default=[], nargs="*")
    group.add_argument("--del-tag-all", action="store_true")
    group.add_argument("--invite", default=[], nargs="*", choices=["email", "manual"])
    identity_parser.set_defaults(func=_identity_function)

    ssh_shell_parser = subparsers.add_parser("ssh-shell")
    ssh_shell_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = ssh_shell_parser.add_argument_group("filter")
    group.add_argument("--name", default=None)
    group.add_argument("--tag", default=None, nargs="*")
    group.add_argument("--boundary", default=None, nargs="*")
    group = ssh_shell_parser.add_argument_group("permission")
    group.add_argument("--username", nargs="*", default=[])
    group.add_argument("--permit-agent-forwarding", action="store_true")
    group.add_argument("--permit-x11-forwarding", action="store_true")
    ssh_shell_parser.set_defaults(func=_ssh_shell_function)

    ssh_port_forwarding_parser = subparsers.add_parser("ssh-port-forwarding")
    ssh_port_forwarding_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = ssh_port_forwarding_parser.add_argument_group("filter")
    group.add_argument("--name", default=None)
    group.add_argument("--tag", default=None, nargs="*")
    group.add_argument("--boundary", default=None, nargs="*")
    group = ssh_port_forwarding_parser.add_argument_group("permission")
    group.add_argument("--username", nargs="*", default=[])
    ssh_port_forwarding_parser.set_defaults(func=_ssh_port_forwarding_function)

    ssh_command_parser = subparsers.add_parser("ssh-command")
    ssh_command_parser.add_argument("-f", "--format", choices=["yaml", "json"], default="yaml")
    group = ssh_command_parser.add_argument_group("filter")
    group.add_argument("--name", default=None)
    group.add_argument("--tag", default=None, nargs="*")
    group.add_argument("--boundary", default=None, nargs="*")
    group = ssh_command_parser.add_argument_group("permission")
    group.add_argument("--username", nargs="*", default=[])
    group.add_argument("--command", nargs="*", default=[])
    ssh_command_parser.set_defaults(func=_ssh_command_function)
