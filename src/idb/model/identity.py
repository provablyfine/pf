import dataclasses
import time

from ..context import ctx
from . import audit_log


@dataclasses.dataclass
class Identity:
    id: int
    name: str
    tag_ids: list[int]
    boundary_ids: list[int]


def create(name: str, boundaries: list[int]) -> int:
    now = int(time.time())
    identity_id = ctx.db.identity.create(name=name, created_at=now)
    for boundary_id in boundaries:
        ctx.db.identity_boundary.create(identity_id=identity_id, boundary_id=boundary_id)
    audit_log.create('identity-create', id=identity_id, name=name, boundaries=boundaries)
    return identity_id


def read_one(id: int):
    identity = ctx.db.identity.read_one(id=id)
    tag_ids = [i.tag_id for i in ctx.db.identity_tag.read_all(identity_id=id)]
    boundary_ids = [i.boundary_id for i in ctx.db.identity_boundary.read_all(identity_id=id)]
    return Identity(id=identity.id, name=identity.name, tag_ids=tag_ids, boundary_ids=boundary_ids)


def format(identity: Identity):
    return {
        'id': identity.id,
        'name': identity.name,
    }
