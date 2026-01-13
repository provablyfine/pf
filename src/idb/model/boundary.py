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

def serialize(boundary, to_client: permission.Converter) -> dict:
    return {
        'id': boundary.id,
        'name': boundary.name,
        'description': boundary.description,
        'ceiling_list': [to_client.convert(g).to_dict() for g in boundary.ceiling_list],
        'denied_list': [to_client.convert(g).to_dict() for g in boundary.denied_list],
    }
