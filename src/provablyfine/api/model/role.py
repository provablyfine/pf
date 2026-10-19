from __future__ import annotations

import dataclasses
import typing

from .. import app_db
from ..context import ctx
from . import audit_log, audit_types, grant, utils


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
    audit_log.create(
        audit_types.ROLE_CREATE,
        refs=audit_log.refs(grants=grant_list),
        id=role_id,
        name=name,
        description=description,
        grant_list=grants,
    )
    return role_id


def delete(id: int) -> bool:
    """Delete a role that has no members. The audit entry keeps what the role contained.

    The row is locked before it is read, so the entry holds what was deleted,
    not what an earlier read of the role saw.

    Return False if the role is already gone, for example deleted by a concurrent request.
    """
    row = ctx.app_db.role.read_one_for_update(id=id)
    if row is None:
        return False
    grants = [grant.deserialize(g) for g in row.grant_list]
    refs = audit_log.refs(grants=grants)
    if ctx.app_db.role.delete(id=id) == 0:
        return False
    audit_log.create(
        audit_types.ROLE_DELETE,
        refs=refs,
        id=id,
        name=row.name,
        description=row.description,
        grant_list=row.grant_list,
    )
    return True


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
    # The entries say what the role held before. The row is locked so that this is what the update replaces.
    old = ctx.app_db.role.read_one_for_update(id=id)
    if name is not None:
        role_fields["name"] = name
        audit_log.create(
            audit_types.ROLE_UPDATE_NAME,
            id=id,
            name=name,
            old=None if old is None else old.name,
        )
    if description is not None:
        role_fields["description"] = description
        audit_log.create(
            audit_types.ROLE_UPDATE_DESCRIPTION,
            id=id,
            description=description,
            old=None if old is None else old.description,
        )

    if grant_list is not None:
        role_fields["grant_list"] = [grant.serialize(g) for g in grant_list]
        audit_log.create(
            audit_types.ROLE_UPDATE_GRANT_LIST,
            refs=audit_log.refs(grants=grant_list),
            id=id,
            grant_list=[grant.serialize(g) for g in grant_list],
            old=None if old is None else old.grant_list,
        )

    if len(role_fields) > 0:
        ctx.app_db.role.update(**role_fields).where(id=id)

    if added_member_id_list is not None and len(added_member_id_list) > 0:
        for member_id in added_member_id_list:
            ctx.app_db.role_member.create(role_id=id, identity_id=member_id)
        audit_log.create(
            audit_types.ROLE_ADD_MEMBERS,
            refs=audit_log.refs(identities=added_member_id_list),
            id=id,
            added_member_id_list=added_member_id_list,
        )
    if deleted_member_id_list is not None and len(deleted_member_id_list) > 0:
        ctx.app_db.role_member.delete(role_id=id, identity_id=deleted_member_id_list)
        audit_log.create(
            audit_types.ROLE_REMOVE_MEMBERS,
            refs=audit_log.refs(identities=deleted_member_id_list),
            id=id,
            deleted_member_id_list=deleted_member_id_list,
        )
