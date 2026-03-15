import dataclasses
import time

from ..context import ctx
from . import audit_log
from . import utils


@dataclasses.dataclass(frozen=True)
class Identity:
    id: int
    name: str
    tag_id_list: list[int]
    boundary_id_list: list[int]


def create(name: str, boundary_id_list: list[int], tag_id_list: list[int]) -> int:
    now = int(time.time())
    identity_id = ctx.db.identity.create(name=name, created_at=now)
    assert identity_id is not None
    for boundary_id in boundary_id_list:
        ctx.db.identity_boundary.create(identity_id=identity_id, boundary_id=boundary_id)
    for tag_id in tag_id_list:
        ctx.db.identity_tag.create(tag_id=tag_id, identity_id=identity_id)
    audit_log.create('identity-create', id=identity_id, name=name, boundary_id_list=boundary_id_list, tag_id_list=tag_id_list)
    return identity_id


def read_one(**kwargs):
    identities = read_all(**kwargs)
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

    output = [Identity(id=i.id, name=i.name, tag_id_list=tag_ids_by_identity_id.get(i.id, []), boundary_id_list=boundary_ids_by_identity_id[i.id]) for i in identities]
    return output


def update(id: int, name: str|None=None, added_tag_id_list: list[int]|None=None, deleted_tag_id_list: list[int]|None=None):
    update_fields = {}
    if name is not None:
        audit_log.create(
            'identity-update-name',
            id=id,
            name=name,
        )
        update_fields['name'] = name

    if len(update_fields) > 0:
        ctx.db.identity.update(**update_fields).where(id=id)

    if added_tag_id_list is not None and len(added_tag_id_list) > 0:
        for tag_id in added_tag_id_list:
            ctx.db.identity_tag.create(tag_id=tag_id, identity_id=id)
        audit_log.create(
            'identity-add-tags',
            id=id,
            added_tag_id_list=added_tag_id_list,
        )
    if deleted_tag_id_list is not None and len(deleted_tag_id_list) > 0:
        ctx.db.identity_tag.delete(identity_id=id, tag_id=deleted_tag_id_list)
        audit_log.create(
            'identity-delete-tags',
            id=id,
            deleted_tag_id_list=deleted_tag_id_list,
        )
