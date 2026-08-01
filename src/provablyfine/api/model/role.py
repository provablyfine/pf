from __future__ import annotations

import dataclasses
import typing

from .. import app_db
from ..context import ctx
from . import audit_log, grant, utils


@dataclasses.dataclass(frozen=True)
class Role:
    id: int
    name: str
    description: str
    grant_list: list[grant.Grant]
    member_id_list: list[int]


def create(name: str, description: str, grant_list: typing.Sequence[grant.Grant]) -> int:
    grants = [grant.serialize(g) for g in grant_list]
    role_id = ctx.app_db.role.create(
        name=name,
        description=description,
        grant_list=grants,
    )
    assert role_id is not None
    audit_log.create("role-create", id=role_id, name=name, description=description, grant_list=grants)
    return role_id


def _from_db(role: app_db.RoleRow, member_id_list: list[int]) -> Role:
    grant_list: list[grant.Grant] = [grant.deserialize(g) for g in role.grant_list]
    return Role(
        id=role.id,
        name=role.name,
        description=role.description,
        grant_list=grant_list,
        member_id_list=member_id_list,
    )


def read_all(**kwargs: typing.Any) -> list[Role]:
    roles = ctx.app_db.role.read_all(**kwargs)
    members = ctx.app_db.role_member.read_all(role_id=list(set(r.id for r in roles)))
    member_id_list_by_role_id = {
        key: [r.identity_id for r in group] for key, group in utils.group_by(members, key=lambda m: m.role_id)
    }
    return [_from_db(r, member_id_list_by_role_id.get(r.id, [])) for r in roles]


def read_one(id: int) -> Role | None:
    roles = read_all(id=id)
    if len(roles) == 0:
        return None
    return roles[0]


def update(
    id: int,
    name: str | None = None,
    description: str | None = None,
    grant_list: list[grant.Grant] | None = None,
    added_member_id_list: list[int] | None = None,
    deleted_member_id_list: list[int] | None = None,
):
    role_fields: dict[str, typing.Any] = {}
    if name is not None:
        role_fields["name"] = name
        audit_log.create(
            "role-update-name",
            id=id,
            name=name,
        )
    if description is not None:
        role_fields["description"] = description
        audit_log.create(
            "role-update-description",
            id=id,
            description=description,
        )

    if grant_list is not None:
        role_fields["grant_list"] = [grant.serialize(g) for g in grant_list]
        audit_log.create(
            "role-update-grant-list",
            id=id,
            permission_list=[grant.serialize(g) for g in grant_list],
        )

    if len(role_fields) > 0:
        ctx.app_db.role.update(**role_fields).where(id=id)

    if added_member_id_list is not None and len(added_member_id_list) > 0:
        for member_id in added_member_id_list:
            ctx.app_db.role_member.create(role_id=id, identity_id=member_id)
        audit_log.create(
            "role-add-members",
            id=id,
            added_member_id_list=added_member_id_list,
        )
    if deleted_member_id_list is not None and len(deleted_member_id_list) > 0:
        ctx.app_db.role_member.delete(role_id=id, identity_id=deleted_member_id_list)
        audit_log.create(
            "role-delete-members",
            id=id,
            deleted_member_id_list=deleted_member_id_list,
        )
