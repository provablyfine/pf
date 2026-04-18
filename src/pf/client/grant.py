from __future__ import annotations

import typing

from . import schemas


def _none(f: typing.Callable[[typing.Any], str]) -> typing.Callable[[typing.Any], str]:
    def wrapper(a: typing.Any) -> str:
        if a is None:
            return "*"
        return f(a)

    return wrapper


def _get_nested(obj: typing.Any, *names: str) -> typing.Any:
    """Get nested attribute from object."""
    result = obj
    for name in names:
        result = getattr(result, name)
        if result is None:
            return None
    return result


def _bool(p: typing.Any, name: str) -> list[str]:
    if not getattr(p, name):
        return []
    return [name]


def _update(p: typing.Any) -> list[str]:
    update = getattr(p, "update")
    if update is None:
        return ["update.*"]
    output: list[str] = []
    for k, v in update.model_dump().items():
        if not v:
            continue
        output.append(f"update.{k}")
    return output


def _name_value(nv: typing.Any) -> str:
    return f"{nv.name}={nv.value}"


def _str(d: typing.Any, name: str) -> list[str]:
    val = getattr(d, name)
    if val is None:
        return []
    return [f"{name}:{val}"]


def _filter_list(d: typing.Any, name: str, f: typing.Callable[[typing.Any], str]) -> list[str]:
    val = getattr(d, name)
    if val is None:
        return []
    if len(val) == 0:
        return [f"{name}:!"]
    return [f"{name}:{','.join(f(i) for i in val)}"]


def _permission_list(d: typing.Any, name: str, f: typing.Callable[[typing.Any], str]) -> list[str]:
    val = getattr(d, name)
    if val is None:
        return [f"{name}:*"]
    if len(val) == 0:
        return []
    return [f"{name}:{','.join(f(i) for i in val)}"]


@_none
def _tag_filter_name_value(nv: schemas.TagNameValue) -> str:
    return f"name_value:{_name_value(nv)}"


def _tag_permission(p: typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _bool(p, "delete")
    return " ".join(output)


def _tag_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    return (
        "tag",
        _tag_filter_name_value(_get_nested(grant, "filter", "name_value")),
        _tag_permission(getattr(grant, "permission")),
    )


@_none
def _role_filter_name(name: str | None) -> str:
    return f"name:{name}"


def _role_permission(p: typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _role_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    return (
        "role",
        _role_filter_name(_get_nested(grant, "filter", "name")),
        _role_permission(getattr(grant, "permission")),
    )


@_none
def _boundary_filter_name(name: str | None) -> str:
    return f"name:{name}"


def _boundary_permission(p: typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _boundary_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    return (
        "boundary",
        _boundary_filter_name(_get_nested(grant, "filter", "name")),
        _boundary_permission(getattr(grant, "permission")),
    )


def _triplet_filter(filter: typing.Any) -> str:
    output: list[str] = (
        _str(filter, "name")
        + _filter_list(filter, "tag_list", _name_value)
        + _filter_list(filter, "boundary_list", lambda i: str(i))
    )
    if len(output) == 0:
        return "*"
    return " ".join(output)


def _identity_permission(p: typing.Any) -> str:
    output: list[str] = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    output += _permission_list(p, "add_tag_list", _name_value)
    output += _permission_list(p, "del_tag_list", _name_value)
    output += _permission_list(p, "invite_list", lambda i: str(i))
    return " ".join(output)


def _identity_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    return (
        "identity",
        _triplet_filter(getattr(grant, "filter")),
        _identity_permission(getattr(grant, "permission")),
    )


def _ssh_shell_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    p = getattr(grant, "permission")
    output: list[str] = (
        _permission_list(p, "username_list", lambda i: str(i))
        + _bool(p, "permit_agent_forwarding")
        + _bool(p, "permit_x11_forwarding")
    )
    return "ssh-shell", _triplet_filter(getattr(grant, "filter")), " ".join(output)


def _ssh_port_forwarding_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    p = getattr(grant, "permission")
    output: list[str] = _permission_list(p, "username_list", lambda i: str(i))
    return "ssh-port-forwarding", _triplet_filter(getattr(grant, "filter")), " ".join(output)


def _ssh_command_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    p = getattr(grant, "permission")
    output: list[str] = _permission_list(p, "username_list", lambda i: str(i)) + _permission_list(
        p, "command_list", lambda i: str(i)
    )
    return "ssh-command", _triplet_filter(getattr(grant, "filter")), " ".join(output)


@_none
def _tenant_filter_id(id: int | None) -> str:
    return f"id:{id}"


def _tenant_permission(p: typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _tenant_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    return (
        "tenant",
        _tenant_filter_id(_get_nested(grant, "filter", "id")),
        _tenant_permission(getattr(grant, "permission")),
    )


@_none
def _auth_filter_name(name: str | None) -> str:
    return f"name:{name}"


def _auth_permission(p: typing.Any) -> str:
    output = _bool(p, "create") + _bool(p, "read") + _update(p) + _bool(p, "delete")
    return " ".join(output)


def _auth_grant_to_text(grant: typing.Any) -> tuple[str, str, str]:
    return (
        "auth",
        _auth_filter_name(_get_nested(grant, "filter", "name")),
        _auth_permission(getattr(grant, "permission")),
    )


def to_text(grant: schemas.Grant) -> tuple[str, str, str]:
    match grant.type:
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
