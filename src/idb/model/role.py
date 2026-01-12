from __future__ import annotations
import dataclasses

from ..context import ctx
from . import audit_log
from . import permission


@dataclasses.dataclass
class Role:
    id: int
    name: str
    description: str
    permission_list: list[permission.Grant]

    @classmethod
    def from_db(cls, role) -> Role:
        return Role(
            id=role.id,
            name=role.name,
            description=role.description,
            permission_list=[permission.Grant.from_dict(g) for g in role.permission_list]
        )


def create(name: str, description: str, permission_list: list[permission.Grant]) -> int:
    permissions = [p.to_dict() for p in permission_list]
    role_id = ctx.db.role.create(
        name=name,
        description=description,
        permission_list=permissions,
    )
    audit_log.create('role-create', id=role_id, name=name, description=description, permission_list=permissions)
    return role_id


def read_all(**kwargs):
    roles = ctx.db.role.read_all(**kwargs)
    return [Role.from_db(r) for r in roles]


def format(id: int):
    role = ctx.db.role.read_one(id=id)
    return  {
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'permissions': role.permissions,
    }
