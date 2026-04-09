from __future__ import annotations

import typing


class TagNameValue(typing.TypedDict):
    name: str
    value: str


class TagFilter(typing.TypedDict):
    name_value: TagNameValue | None


class TagPermission(typing.TypedDict):
    create: bool
    read: bool
    delete: bool


class TagGrantDict(typing.TypedDict):
    type: typing.Literal["tag"]
    filter: TagFilter
    permission: TagPermission


class RoleUpdatePermission(typing.TypedDict):
    name: bool
    description: bool
    grant_list: bool
    member_list: bool


class RolePermission(typing.TypedDict):
    create: bool
    read: bool
    delete: bool
    update: RoleUpdatePermission | None


class RoleFilter(typing.TypedDict):
    name: str | None


class RoleGrantDict(typing.TypedDict):
    type: typing.Literal["role"]
    filter: RoleFilter
    permission: RolePermission


class BoundaryUpdatePermission(typing.TypedDict):
    name: bool
    description: bool
    ceiling_list: bool
    denied_list: bool


class BoundaryPermission(typing.TypedDict):
    create: bool
    read: bool
    delete: bool
    update: BoundaryUpdatePermission | None


class BoundaryFilter(typing.TypedDict):
    name: str | None


class BoundaryGrantDict(typing.TypedDict):
    type: typing.Literal["boundary"]
    filter: BoundaryFilter
    permission: BoundaryPermission


class TripletFilter(typing.TypedDict):
    name: str | None
    tag_list: list[TagNameValue] | None
    boundary_list: list[str] | None


class IdentityCreatePermission(typing.TypedDict):
    allowed: bool
    allowed_tag_list: list[TagNameValue] | None
    required_boundary_list: list[str] | None


class IdentityUpdatePermission(typing.TypedDict):
    name: bool


class IdentityPermission(typing.TypedDict):
    create: IdentityCreatePermission | None
    read: bool
    update: IdentityUpdatePermission | None
    delete: bool
    add_tag_list: list[TagNameValue] | None
    del_tag_list: list[TagNameValue] | None
    invite_list: list[str] | None


class IdentityGrantDict(typing.TypedDict):
    type: typing.Literal["identity"]
    filter: TripletFilter
    permission: IdentityPermission


class SSHShellPermission(typing.TypedDict):
    username_list: list[str]
    permit_agent_forwarding: bool
    permit_x11_forwarding: bool


class SSHShellGrantDict(typing.TypedDict):
    type: typing.Literal["ssh-shell"]
    filter: TripletFilter
    permission: SSHShellPermission


class SSHPortForwardingPermission(typing.TypedDict):
    username_list: list[str]


class SSHPortForwardingGrantDict(typing.TypedDict):
    type: typing.Literal["ssh-port-forwarding"]
    filter: TripletFilter
    permission: SSHPortForwardingPermission


class SSHCommandPermission(typing.TypedDict):
    username_list: list[str]
    command_list: list[str]


class SSHCommandGrantDict(typing.TypedDict):
    type: typing.Literal["ssh-command"]
    filter: TripletFilter
    permission: SSHCommandPermission


class TenantUpdatePermission(typing.TypedDict):
    display_name: bool
    is_enabled: bool


class TenantPermission(typing.TypedDict):
    create: bool
    read: bool
    delete: bool
    update: TenantUpdatePermission | None


class TenantFilter(typing.TypedDict):
    id: int | None


class TenantGrantDict(typing.TypedDict):
    type: typing.Literal["tenant"]
    filter: TenantFilter
    permission: TenantPermission


class AuthUpdatePermission(typing.TypedDict):
    name: bool
    description: bool
    is_enabled: bool
    config: bool


class AuthPermission(typing.TypedDict):
    create: bool
    read: bool
    delete: bool
    update: AuthUpdatePermission | None


class AuthFilter(typing.TypedDict):
    name: str | None


class AuthGrantDict(typing.TypedDict):
    type: typing.Literal["auth"]
    filter: AuthFilter
    permission: AuthPermission


class InvalidGrantDict(typing.TypedDict):
    type: typing.Literal["invalid"]
    filter: dict[typing.Any, typing.Any]
    permission: dict[typing.Any, typing.Any]


GrantDict = (
    TagGrantDict
    | RoleGrantDict
    | BoundaryGrantDict
    | IdentityGrantDict
    | SSHShellGrantDict
    | SSHPortForwardingGrantDict
    | SSHCommandGrantDict
    | TenantGrantDict
    | AuthGrantDict
    | InvalidGrantDict
)


def _none(f: typing.Callable[[typing.Any], str]) -> typing.Callable[[typing.Any], str]:
    def wrapper(a: typing.Any) -> str:
        if a is None:
            return "*"
        return f(a)

    return wrapper


def _bool(p: dict[str, typing.Any] | typing.Any, name: str) -> list[str]:
    if not p[name]:
        return []
    return [name]


def _update(p: dict[str, typing.Any] | typing.Any) -> list[str]:
    if p["update"] is None:
        return ["update.*"]
    output: list[str] = []
    for k, v in p["update"].items():
        if not v:
            continue
        output.append(f"update.{k}")
    return output


def _name_value(nv: TagNameValue) -> str:
    return f"{nv['name']}={nv['value']}"


def _str(d: dict[str, typing.Any] | typing.Any, name: str) -> list[str]:
    if d[name] is None:
        return []
    return [f"{name}:{d[name]}"]


def _filter_list(d: dict[str, typing.Any] | typing.Any, name: str, f: typing.Callable[[typing.Any], str]) -> list[str]:
    if d[name] is None:
        return []
    if len(d[name]) == 0:
        return [f"{name}:!"]
    return [f"{name}:{','.join(f(i) for i in d[name])}"]


def _permission_list(
    d: dict[str, typing.Any] | typing.Any, name: str, f: typing.Callable[[typing.Any], str]
) -> list[str]:
    if d[name] is None:
        return [f"{name}:*"]
    if len(d[name]) == 0:
        return []
    return [f"{name}:{','.join(f(i) for i in d[name])}"]


@_none
def _tag_filter_name_value(nv: TagNameValue) -> str:
    return f"name_value:{_name_value(nv)}"


def _tag_permission(p: dict[str, typing.Any] | typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _bool(p, "delete")
    return " ".join(output)


def _tag_grant_to_text(grant: TagGrantDict) -> tuple[str, str, str]:
    return "tag", _tag_filter_name_value(grant["filter"]["name_value"]), _tag_permission(grant["permission"])


@_none
def _role_filter_name(name: str | None) -> str:
    return f"name:{name}"


def _role_permission(p: dict[str, typing.Any] | typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _role_grant_to_text(grant: RoleGrantDict) -> tuple[str, str, str]:
    return "role", _role_filter_name(grant["filter"]["name"]), _role_permission(grant["permission"])


@_none
def _boundary_filter_name(name: str | None) -> str:
    return f"name:{name}"


def _boundary_permission(p: dict[str, typing.Any] | typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _boundary_grant_to_text(grant: BoundaryGrantDict) -> tuple[str, str, str]:
    return "boundary", _boundary_filter_name(grant["filter"]["name"]), _boundary_permission(grant["permission"])


def _triplet_filter(filter: TripletFilter) -> str:
    output: list[str] = (
        _str(filter, "name")
        + _filter_list(filter, "tag_list", _name_value)
        + _filter_list(filter, "boundary_list", lambda i: str(i))
    )
    if len(output) == 0:
        return "*"
    return " ".join(output)


def _identity_permission(p: dict[str, typing.Any] | typing.Any) -> str:
    output: list[str] = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    output += _permission_list(p, "add_tag_list", _name_value)
    output += _permission_list(p, "del_tag_list", _name_value)
    output += _permission_list(p, "invite_list", lambda i: str(i))
    return " ".join(output)


def _identity_grant_to_text(grant: IdentityGrantDict) -> tuple[str, str, str]:
    return "identity", _triplet_filter(grant["filter"]), _identity_permission(grant["permission"])


def _ssh_shell_grant_to_text(grant: SSHShellGrantDict) -> tuple[str, str, str]:
    p = grant["permission"]
    output: list[str] = (
        _permission_list(p, "username_list", lambda i: str(i))
        + _bool(p, "permit_agent_forwarding")
        + _bool(p, "permit_x11_forwarding")
    )
    return "ssh-shell", _triplet_filter(grant["filter"]), " ".join(output)


def _ssh_port_forwarding_grant_to_text(grant: SSHPortForwardingGrantDict) -> tuple[str, str, str]:
    p = grant["permission"]
    output: list[str] = _permission_list(p, "username_list", lambda i: str(i))
    return "ssh-port-forwarding", _triplet_filter(grant["filter"]), " ".join(output)


def _ssh_command_grant_to_text(grant: SSHCommandGrantDict) -> tuple[str, str, str]:
    p = grant["permission"]
    output: list[str] = _permission_list(p, "username_list", lambda i: str(i)) + _permission_list(
        p, "command_list", lambda i: str(i)
    )
    return "ssh-command", _triplet_filter(grant["filter"]), " ".join(output)


@_none
def _tenant_filter_id(id: int | None) -> str:
    return f"id:{id}"


def _tenant_permission(p: dict[str, typing.Any] | typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _tenant_grant_to_text(grant: TenantGrantDict) -> tuple[str, str, str]:
    return "tenant", _tenant_filter_id(grant["filter"]["id"]), _tenant_permission(grant["permission"])


@_none
def _auth_filter_name(name: str | None) -> str:
    return f"name:{name}"


def _auth_permission(p: dict[str, typing.Any] | typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _auth_grant_to_text(grant: AuthGrantDict) -> tuple[str, str, str]:
    return "auth", _auth_filter_name(grant["filter"]["name"]), _auth_permission(grant["permission"])


def to_text(grant: GrantDict) -> tuple[str, str, str]:
    match grant["type"]:
        case "tag":
            return _tag_grant_to_text(grant)
        case "role":
            return _role_grant_to_text(grant)
        case "boundary":
            return _boundary_grant_to_text(grant)
        case "identity":
            return _identity_grant_to_text(grant)
        case "ssh-shell":
            return _ssh_shell_grant_to_text(grant)
        case "ssh-port-forwarding":
            return _ssh_port_forwarding_grant_to_text(grant)
        case "ssh-command":
            return _ssh_command_grant_to_text(grant)
        case "tenant":
            return _tenant_grant_to_text(grant)
        case "auth":
            return _auth_grant_to_text(grant)
        case "invalid":
            return "invalid", "!", "!"
        case _:
            raise AssertionError("unreachable")
