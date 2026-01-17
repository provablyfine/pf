from __future__ import annotations
import dataclasses

from ..context import ctx
from . import utils
from . import audit_log
from . import permission


@dataclasses.dataclass(frozen=True)
class Role:
    id: int
    name: str
    description: str
    permission_list: list[permission.Grant]
    member_id_list: list[int]


def create(name: str, description: str, permission_list: list[permission.Grant]) -> int:
    permissions = [p.to_dict() for p in permission_list]
    role_id = ctx.db.role.create(
        name=name,
        description=description,
        permission_list=permissions,
    )
    audit_log.create('role-create', id=role_id, name=name, description=description, permissions=permissions)
    return role_id


def _from_db(role, member_id_list: list[int]) -> Role:
    return Role(
        id=role.id,
        name=role.name,
        description=role.description,
        permission_list=[permission.Grant.from_dict(g) for g in role.permission_list],
        member_id_list=member_id_list,
    )


def read_all(**kwargs):
    roles = ctx.db.role.read_all(**kwargs)
    members = ctx.db.role_member.read_all(role_id=list(set(r.id for r in roles)))
    member_id_list_by_role_id = {key: [r.identity_id for r in group] for key, group in utils.group_by(members, key=lambda m: m.role_id)}
    return [_from_db(r, member_id_list_by_role_id.get(r.id, [])) for r in roles]


def read_one(id):
    roles = read_all(id=id)
    if len(roles) == 0:
        return None
    return roles[0]


def update(role: Role, description: str=None, permission_list: list[permission.Grant]=None, member_id_list: list[int]=None):
    role_fields = {}
    if description is not None and role.description != description:
        role_fields['description'] = description
        audit_log.create(
            'role-update-description',
            id=role.id,
            description=description,
        )

    if permission_list is not None:
        role_fields['permission_list'] = [p.to_dict() for p in permission_list]
        current_permission_list = set(role.permission_list)
        new_permission_list = set(permission_list)
        added_permission_list = new_permission_list.difference(current_permission_list)
        deleted_permission_list = current_permission_list.difference(new_permission_list)
        audit_log.create(
            'role-update-permissions',
            id=role.id,
            permissions_added=[p.to_dict() for p in added_permission_list],
            permissions_deleted=[p.to_dict() for p in deleted_permission_list],
        )

    if len(role_fields) > 0:
        ctx.db.role.update(**role_fields).where(id=role.id)

    if member_id_list is not None:
        current_member_ids = set(role.member_id_list)
        new_member_ids = set(member_id_list)
        added_member_ids = new_member_ids.difference(current_member_ids)
        deleted_member_ids = current_member_ids.difference(new_member_ids)
        if len(deleted_member_ids) > 0:
            ctx.db.role_member.delete(role_id=role.id, identity_id=deleted_member_ids)
        if len(added_member_ids):
            for member_id in added_member_ids:
                ctx.db.role_member.create(role_id=role.id, identity_id=member_id)
        audit_log.create(
            'role-update-members',
            id=role.id,
            member_id_added_list=list(added_member_ids),
            member_id_deleted_list=list(deleted_member_ids)
        )


def serialize(role: Role, to_client: permission.Converter):
    members = ctx.db.identity.read_all(id=list(set(role.member_id_list)))
    serialized_members = [{'id': m.id, 'name': m.name} for m in members]
    serialized = {
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'permissions': [to_client.convert(permission).to_dict() for permission in role.permission_list],
        'members': serialized_members,
    }
    return serialized
