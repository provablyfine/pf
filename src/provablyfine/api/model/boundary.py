import dataclasses
import typing

from ... import _sentinel
from .. import app_db
from ..context import ctx
from . import audit_log, audit_types, grant


@dataclasses.dataclass
class Boundary:
    id: int
    name: str
    description: str
    ceiling_list: list[grant.Grant] | None
    denied_list: list[grant.Grant]


def create(
    name: str, description: str, ceiling_list: typing.Sequence[grant.Grant] | None, denied_list: list[grant.Grant]
) -> int:
    db_ceiling_list = None if ceiling_list is None else [grant.serialize(g) for g in ceiling_list]
    db_denied_list = [grant.serialize(g) for g in denied_list]
    boundary_id = ctx.app_db.boundary.create(
        name=name,
        description=description,
        ceiling_list=db_ceiling_list,
        denied_list=db_denied_list,
    )
    assert boundary_id is not None  # we just created it
    audit_log.create(
        audit_types.BOUNDARY_CREATE,
        refs=audit_log.refs(grants=[*(ceiling_list or []), *denied_list]),
        id=boundary_id,
        name=name,
        description=description,
        ceiling_list=db_ceiling_list,
        denied_list=db_denied_list,
    )
    return boundary_id


def delete(id: int) -> bool:
    """Delete a boundary that no identity uses. The audit entry keeps what the boundary contained.

    The row is locked before it is read, so the entry holds what was deleted,
    not what an earlier read of the boundary saw.

    Return False if the boundary is already gone, for example deleted by a concurrent request.
    """
    row = ctx.app_db.boundary.read_one_for_update(id=id)
    if row is None:
        return False
    boundary = _from_db(row)
    refs = audit_log.refs(grants=[*(boundary.ceiling_list or []), *boundary.denied_list])
    if ctx.app_db.boundary.delete(id=id) == 0:
        return False
    audit_log.create(
        audit_types.BOUNDARY_DELETE,
        refs=refs,
        id=id,
        name=row.name,
        description=row.description,
        ceiling_list=row.ceiling_list,
        denied_list=row.denied_list,
    )
    return True


def _from_db(b: app_db.BoundaryRow) -> Boundary:
    return Boundary(
        id=b.id,
        name=b.name,
        description=b.description,
        ceiling_list=None if b.ceiling_list is None else [grant.deserialize(g) for g in b.ceiling_list],
        denied_list=[grant.deserialize(g) for g in b.denied_list],
    )


def read_all(**kwargs: typing.Any) -> list[Boundary]:
    boundaries = ctx.app_db.boundary.read_all(**kwargs)
    return [_from_db(b) for b in boundaries]


def read_one(**kwargs: typing.Any) -> Boundary | None:
    boundary = ctx.app_db.boundary.read_one(**kwargs)
    if boundary is None:
        return None
    return _from_db(boundary)


def update(
    id: int,
    name: str | _sentinel.Unset = _sentinel.UNSET,
    description: str | _sentinel.Unset = _sentinel.UNSET,
    ceiling_list: list[grant.Grant] | _sentinel.Unset | None = _sentinel.UNSET,
    denied_list: list[grant.Grant] | _sentinel.Unset = _sentinel.UNSET,
) -> None:
    update_fields: dict[str, typing.Any] = {}
    # The entries say what the boundary held before. The row is locked so that this is what the update replaces.
    old = ctx.app_db.boundary.read_one_for_update(id=id)
    if not isinstance(name, _sentinel.Unset):
        update_fields["name"] = name
        audit_log.create(
            audit_types.BOUNDARY_UPDATE_NAME,
            id=id,
            name=name,
            old=None if old is None else old.name,
        )
    if not isinstance(description, _sentinel.Unset):
        update_fields["description"] = description
        audit_log.create(
            audit_types.BOUNDARY_UPDATE_DESCRIPTION,
            id=id,
            description=description,
            old=None if old is None else old.description,
        )
    if not isinstance(ceiling_list, _sentinel.Unset):
        db_ceiling_list = None if ceiling_list is None else [grant.serialize(g) for g in ceiling_list]
        update_fields["ceiling_list"] = db_ceiling_list
        audit_log.create(
            audit_types.BOUNDARY_UPDATE_CEILING_LIST,
            refs=audit_log.refs(grants=ceiling_list or []),
            id=id,
            ceiling_list=db_ceiling_list,
            old=None if old is None else old.ceiling_list,
        )
    if not isinstance(denied_list, _sentinel.Unset):
        db_denied_list = [grant.serialize(g) for g in denied_list]
        update_fields["denied_list"] = db_denied_list
        audit_log.create(
            audit_types.BOUNDARY_UPDATE_DENIED_LIST,
            refs=audit_log.refs(grants=denied_list),
            id=id,
            denied_list=db_denied_list,
            old=None if old is None else old.denied_list,
        )
    if len(update_fields) == 0:
        return
    ctx.app_db.boundary.update(**update_fields).where(id=id)
