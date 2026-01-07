from ..context import ctx
from . import audit_log


def create(name: str, boundaries: list[int]) -> int:
    identity_id = ctx.db.identity.create(name=name, boundaries=boundaries, detail={})
    audit_log.create('identity-create', id=identity_id, name=name, boundaries=boundaries)
    return identity_id


def format(id: int):
    identity = ctx.db.identity.read_one(id=id)
    return {
        'id': identity.id,
        'name': identity.name,
        'boundaries': identity.boundaries,
    }
