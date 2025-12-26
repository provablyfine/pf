from ..context import ctx
from . import audit_log


def create(name: str, description: str, permissions: list[str]) -> int:
    role_id = ctx.db.audit_log.create(name=name, description=description, permissions=permissions)
    audit_log.create('role-create', id=role_id, name=name, description=description, permissions=permissions)
    return role_id


def format(id: int):
    role = ctx.db.role.read_one(id=id)
    return  {
        'id': role.id,
        'name': role.name,
        'description': role.description,
        'permissions': role.permissions,
    }
