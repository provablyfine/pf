from ..context import ctx
from . import audit_log


def create(name, boundary_id: int) -> int:
    identity_id = ctx.db.identity.create(name=name, boundary_id=boundary_id, detail={})
    audit_log.create('identity-create', id=identity_id, name=name, boundary_id=boundary_id)
    return identity_id


def format(id: int):
    identity = ctx.db.identity.read_one(id=id)
    return {
        'id': identity.id,
        'name': identity.name,
        'boundary_id': identity.boundary_id,
    }
