import copy

from ..context import ctx

from . import audit_log


def create(name: str, description: str, denies: list[str] = None) -> int:
    if denies is None:
        denies = []
    boundary_id = ctx.db.boundary.create(name=name, description=description, denies=denies)
    audit_log.create('boundary-create', id=boundary_id, name=name, description=description, denies=denies)
    return boundary_id


def format(id: int):
    boundary = ctx.db.boundary.read_one(id=id)
    return {
        'id': boundary.id,
        'name': boundary.name,
        'description': boundary.description,
        'denies': boundary.denies,
    }
