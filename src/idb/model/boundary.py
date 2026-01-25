import dataclasses

from ..context import ctx

from . import audit_log
from . import permission


@dataclasses.dataclass
class Boundary:
    id: int
    name: str
    description: str
    ceiling_list: list[permission.Grant]
    denied_list: list[permission.Grant]


def create(name: str, description: str, ceiling_list: list[permission.Grant]=None, denied_list: list[permission.Grant]=None) -> int:
    if ceiling_list is None:
        ceiling_list = []
    if denied_list is None:
        denied_list = []
    ceiling_list = [g.to_dict() for g in ceiling_list]
    denied_list = [g.to_dict() for g in denied_list]
    boundary_id = ctx.db.boundary.create(
        name=name,
        description=description,
        ceiling_list=ceiling_list,
        denied_list=denied_list,
    )
    audit_log.create('boundary-create', id=boundary_id, name=name, description=description, ceiling_list=ceiling_list, denied_list=denied_list)
    return boundary_id


def _from_db(b):
    return Boundary(
        id=b.id,
        name=b.name,
        description=b.description,
        ceiling_list=[permission.Grant.from_dict(p) for p in b.ceiling_list],
        denied_list=[permission.Grant.from_dict(p) for p in b.denied_list],
    )


def read_all(**kwargs):
    boundaries = ctx.db.boundary.read_all(**kwargs)
    return [_from_db(b) for b in boundaries]


def read_one(**kwargs):
    boundary = ctx.db.boundary.read_one(**kwargs)
    if boundary is None:
        return None
    return _from_db(boundary)


def update(id: int, name: str=None, description: str=None, ceiling_list: list[permission.Grant]=None, denied_list: list[permission.Grant]=None):
    update_fields = {}
    if name is not None:
        update_fields['name'] = name
        audit_log.create(
            'boundary-update-name',
            id=id,
            name=name,
        )
    if description is not None:
        update_fields['description'] = description
        audit_log.create(
            'boundary-update-description',
            id=id,
            description=description,
        )
    if ceiling_list is not None:
        tmp = [g.to_dict() for g in ceiling_list]
        update_fields['ceiling_list'] = tmp
        audit_log.create(
            'boundary-update-ceiling-list',
            id=id,
            denied_list=tmp,
        )
    if denied_list is not None:
        tmp = [g.to_dict() for g in denied_list]
        update_fields['denied_list'] = tmp
        audit_log.create(
            'boundary-update-denied-list',
            id=id,
            denied_list=tmp,
        )
    if len(update_fields) == 0:
        return
    ctx.db.boundary.update(**update_fields).where(id=id)


def serialize(boundary, to_client: permission.Converter) -> dict:
    return {
        'id': boundary.id,
        'name': boundary.name,
        'description': boundary.description,
        'ceiling_list': permission.serialize_list(boundary.ceiling_list, to_client),
        'denied_list': permission.serialize_list(boundary.denied_list, to_client),
    }
