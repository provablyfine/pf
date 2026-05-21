import dataclasses
import typing

from .. import app_db
from ..context import ctx
from . import audit_log, grant


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
        "boundary-create",
        id=boundary_id,
        name=name,
        description=description,
        ceiling_list=db_ceiling_list,
        denied_list=db_denied_list,
    )
    return boundary_id


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


class Unset:
    pass


_UNSET = Unset()


def update(
    id: int,
    name: str | Unset = _UNSET,
    description: str | Unset = _UNSET,
    ceiling_list: list[grant.Grant] | None | Unset = _UNSET,
    denied_list: list[grant.Grant] | Unset = _UNSET,
) -> None:
    update_fields: dict[str, typing.Any] = {}
    if not isinstance(name, Unset):
        update_fields["name"] = name
        audit_log.create(
            "boundary-update-name",
            id=id,
            name=name,
        )
    if not isinstance(description, Unset):
        update_fields["description"] = description
        audit_log.create(
            "boundary-update-description",
            id=id,
            description=description,
        )
    if not isinstance(ceiling_list, Unset):
        db_ceiling_list = None if ceiling_list is None else [grant.serialize(g) for g in ceiling_list]
        update_fields["ceiling_list"] = db_ceiling_list
        audit_log.create(
            "boundary-update-ceiling-list",
            id=id,
            ceiling_list=db_ceiling_list,
        )
    if not isinstance(denied_list, Unset):
        db_denied_list = [grant.serialize(g) for g in denied_list]
        update_fields["denied_list"] = db_denied_list
        audit_log.create(
            "boundary-update-denied-list",
            id=id,
            denied_list=db_denied_list,
        )
    if len(update_fields) == 0:
        return
    ctx.app_db.boundary.update(**update_fields).where(id=id)
