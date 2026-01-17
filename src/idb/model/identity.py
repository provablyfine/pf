import dataclasses
import time

from ..context import ctx
from . import audit_log
from . import utils


@dataclasses.dataclass(frozen=True)
class Identity:
    id: int
    name: str
    tag_ids: tuple[int]
    boundary_ids: tuple[int]


def create(name: str, boundary_ids: list[int]) -> int:
    now = int(time.time())
    identity_id = ctx.db.identity.create(name=name, created_at=now)
    for boundary_id in boundary_ids:
        ctx.db.identity_boundary.create(identity_id=identity_id, boundary_id=boundary_id)
    audit_log.create('identity-create', id=identity_id, name=name, boundary_ids=boundary_ids)
    return identity_id


def read_one(id: int):
    identities = read_all(id=id)
    if len(identities) == 0:
        return None
    return identities[0]


def read_all(**kwargs):
    # prepare query
    id_filter = []
    if 'id' in kwargs:
        ids = kwargs['id']
        if isinstance(ids, int):
            ids = [ids]
        id_filter.append(ids)
    if 'tag_id' in kwargs:
        tag_identity_ids = [it.identity_id for it in ctx.db.identity_tag.read_all(tag_id=kwargs['tag_id'])]
        id_filter.append(tag_identity_ids)
    if 'tag_name' in kwargs:
        tag_ids = [t.id for t in ctx.db.tag.read_all(name=kwargs['tag_name'])]
        tag_identity_ids = [it.identity_id for it in ctx.db.identity_tag.read_all(tag_id=tag_ids)]
        id_filter.append(tag_identity_ids)
    if 'boundary_id' in kwargs:
        boundary_identity_ids = [ib.identity_id for ib in ctx.db.identity_boundary.read_all(boundary_id=kwargs['boundary_id'])]
        id_filter.append(boundary_identity_ids)
    if 'boundary_name' in kwargs:
        boundary_ids = [b.id for b in ctx.db.boundary.read_all(name=kwargs['boundary_name'])]
        boundary_identity_ids = [ib.identity_id for ib in ctx.db.identity_boundary.read_all(boundary_id=boundary_ids)]
        id_filter.append(boundary_identity_ids)
    query = {}
    if len(id_filter) > 0:
        id_set = set(id_filter[0])
        remaining_id_filter = id_filter[1:]
        if len(remaining_id_filter) > 0:
            id_set = id_set.intersection(set(i) for i in remaining_id_filter)
        query['id'] = list(id_set)
    if 'name' in kwargs:
        query['name'] = kwargs['name']

    # run query
    identities = ctx.db.identity.read_all(**query)

    # Now, format output
    identity_ids = [i.id for i in identities]
    identity_tags = ctx.db.identity_tag.read_all(identity_id=identity_ids)
    tag_ids_by_identity_id = {identity_id: [it.tag_id for it in group] for identity_id, group in utils.group_by(identity_tags, key=lambda it: it.identity_id)}
    identity_boundaries = ctx.db.identity_boundary.read_all(identity_id=identity_ids)
    boundary_ids_by_identity_id = {boundary_id: [ib.boundary_id for ib in group] for boundary_id, group in utils.group_by(identity_boundaries, key=lambda ib: ib.identity_id)}

    output = [Identity(id=i.id, name=i.name, tag_ids=tag_ids_by_identity_id.get(i.id, []), boundary_ids=boundary_ids_by_identity_id[i.id]) for i in identities]
    return output


def serialize(identities: list[Identity]) -> dict:
    # read the data we need to format fully the output.
    tags = ctx.db.tag.read_all(id=list(set(tag_id for i in identities for tag_id in i.tag_ids)))
    boundaries = ctx.db.boundary.read_all(id=list(set(boundary_id for i in identities for boundary_id in i.boundary_ids)))
    tag_by_id = {t.id: {'id': t.id, 'name': t.name, 'value': t.value} for t in tags}
    boundary_by_id = {b.id: {'id': b.id, 'name': b.name} for b in boundaries}

    def serialize_identity(i):
        return {
            'id': i.id,
            'name': i.name,
            'tags': [tag_by_id[tag_id] for tag_id in i.tag_ids],
            'boundaries': [boundary_by_id[boundary_id] for boundary_id in i.boundary_ids],
        }

    # format the output in one go.
    return {i.id: serialize_identity(i) for i in identities}


def serialize_one(identity: Identity) -> dict:
    by = serialize([identity])
    return by[identity.id]
