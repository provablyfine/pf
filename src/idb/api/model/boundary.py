import dataclasses

from ..context import ctx

from . import audit_log
from . import grant


@dataclasses.dataclass
class Boundary:
    id: int
    name: str
    description: str
    ceiling_list: list[grant.Grant]|None
    denied_list: list[grant.Grant]


def create(name: str, description: str, ceiling_list: list[grant.Grant]|None, denied_list: list[grant.Grant]) -> int:
    db_ceiling_list = None if ceiling_list is None else [g.to_db_dict() for g in ceiling_list]
    db_denied_list = [g.to_db_dict() for g in denied_list]
    boundary_id = ctx.db.boundary.create(
        name=name,
        description=description,
        ceiling_list=db_ceiling_list,
        denied_list=db_denied_list,
    )
    audit_log.create('boundary-create', id=boundary_id, name=name, description=description, ceiling_list=db_ceiling_list, denied_list=db_denied_list)
    return boundary_id


def _from_db(b):
    return Boundary(
        id=b.id,
        name=b.name,
        description=b.description,
        ceiling_list=[grant.Grant.from_db_dict(p) for p in b.ceiling_list],
        denied_list=[grant.Grant.from_db_dict(p) for p in b.denied_list],
    )


def read_all(**kwargs):
    boundaries = ctx.db.boundary.read_all(**kwargs)
    return [_from_db(b) for b in boundaries]


def read_one(**kwargs):
    boundary = ctx.db.boundary.read_one(**kwargs)
    if boundary is None:
        return None
    return _from_db(boundary)


def update(id: int, name: str=None, description: str=None, ceiling_list: list[grant.Grant]|None=None, denied_list: list[grant.Grant]|None=None):
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
        db_ceiling_list = [g.to_db_dict() for g in ceiling_list]
        update_fields['ceiling_list'] = db_ceiling_list
        audit_log.create(
            'boundary-update-ceiling-list',
            id=id,
            ceiling_list=db_ceiling_list,
        )
    if denied_list is not None:
        db_denied_list = [g.to_db_dict() for g in denied_list]
        update_fields['denied_list'] = db_denied_list
        audit_log.create(
            'boundary-update-denied-list',
            id=id,
            denied_list=db_denied_list,
        )
    if len(update_fields) == 0:
        return
    ctx.db.boundary.update(**update_fields).where(id=id)


def to_client_dict(boundary, serializer: grant.ClientSerializer) -> dict:
    return {
        'id': boundary.id,
        'name': boundary.name,
        'description': boundary.description,
        'ceiling_list': [g.to_client_dict(serializer) for g in boundary.ceiling_list],
        'denied_list': [g.to_client_dict(serializer) for g in boundary.denied_list],
    }
