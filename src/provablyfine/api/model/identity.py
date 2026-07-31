import dataclasses
import re
import time
import typing

from ... import _sentinel
from ..context import ctx
from . import audit_log, utils

_STANDALONE_UNIX_USERNAME_RE = re.compile(r"^u([0-9a-f]+)$")


@dataclasses.dataclass(frozen=True)
class Identity:
    id: int
    name: str
    tag_id_list: list[int]
    boundary_id_list: list[int]
    unix_username: str | None


def create(name: str, boundary_id_list: list[int], tag_id_list: list[int]) -> int:
    now = int(time.time())
    identity_id = ctx.app_db.identity.create(name=name, created_at=now)
    assert identity_id is not None
    for boundary_id in boundary_id_list:
        ctx.app_db.identity_boundary.create(identity_id=identity_id, boundary_id=boundary_id)
    for tag_id in tag_id_list:
        ctx.app_db.identity_tag.create(tag_id=tag_id, identity_id=identity_id)
    audit_log.create(
        "identity-create", id=identity_id, name=name, boundary_id_list=boundary_id_list, tag_id_list=tag_id_list
    )
    return identity_id


def read_one(**kwargs: typing.Any) -> Identity | None:
    identities = read_all(**kwargs)
    if len(identities) == 0:
        return None
    return identities[0]


def read_all(**kwargs: typing.Any) -> list[Identity]:
    id_filter: list[list[int]] = []
    if "id" in kwargs:
        ids: int | list[int] = kwargs["id"]
        if isinstance(ids, int):
            ids = [ids]
        id_filter.append(ids)
    if "tag_id" in kwargs:
        tag_identity_ids = [it.identity_id for it in ctx.app_db.identity_tag.read_all(tag_id=kwargs["tag_id"])]
        id_filter.append(tag_identity_ids)
    if "tag_name" in kwargs:
        tag_ids = [t.id for t in ctx.app_db.tag.read_all(name=kwargs["tag_name"])]
        tag_identity_ids = [it.identity_id for it in ctx.app_db.identity_tag.read_all(tag_id=tag_ids)]
        id_filter.append(tag_identity_ids)
    if "boundary_id" in kwargs:
        boundary_identity_ids = [
            ib.identity_id for ib in ctx.app_db.identity_boundary.read_all(boundary_id=kwargs["boundary_id"])
        ]
        id_filter.append(boundary_identity_ids)
    if "boundary_name" in kwargs:
        boundary_ids = [b.id for b in ctx.app_db.boundary.read_all(name=kwargs["boundary_name"])]
        boundary_identity_ids = [
            ib.identity_id for ib in ctx.app_db.identity_boundary.read_all(boundary_id=boundary_ids)
        ]
        id_filter.append(boundary_identity_ids)
    query: dict[str, typing.Any] = {}
    if len(id_filter) > 0:
        id_set: set[int] = set(id_filter[0])
        remaining_id_filter = id_filter[1:]
        if len(remaining_id_filter) > 0:
            id_set = id_set.intersection(set(i) for i in remaining_id_filter)
        query["id"] = list(id_set)
    if "name" in kwargs:
        query["name"] = kwargs["name"]

    identities = ctx.app_db.identity.read_all(**query)

    identity_ids = [i.id for i in identities]
    identity_tags = ctx.app_db.identity_tag.read_all(identity_id=identity_ids)
    tag_ids_by_identity_id: dict[int, list[int]] = {
        identity_id: [it.tag_id for it in group]
        for identity_id, group in utils.group_by(identity_tags, key=lambda it: it.identity_id)
    }
    identity_boundaries = ctx.app_db.identity_boundary.read_all(identity_id=identity_ids)
    boundary_ids_by_identity_id: dict[int, list[int]] = {
        identity_id: [ib.boundary_id for ib in group]
        for identity_id, group in utils.group_by(identity_boundaries, key=lambda ib: ib.identity_id)
    }

    output = [
        Identity(
            id=i.id,
            name=i.name,
            tag_id_list=tag_ids_by_identity_id.get(i.id, []),
            boundary_id_list=boundary_ids_by_identity_id[i.id],
            unix_username=i.unix_username,
        )
        for i in identities
    ]
    return output


def update(
    id: int,
    name: str | _sentinel.Unset = _sentinel.UNSET,
    added_tag_id_list: list[int] | _sentinel.Unset = _sentinel.UNSET,
    deleted_tag_id_list: list[int] | _sentinel.Unset = _sentinel.UNSET,
    unix_username: str | None | _sentinel.Unset = _sentinel.UNSET,
) -> None:
    update_fields: dict[str, typing.Any] = {}
    if name is not _sentinel.UNSET:
        audit_log.create(
            "identity-update-name",
            id=id,
            name=name,
        )
        update_fields["name"] = name
    if unix_username is not _sentinel.UNSET:
        audit_log.create("identity-update-unix-username", id=id, unix_username=unix_username)
        update_fields["unix_username"] = unix_username

    if len(update_fields) > 0:
        ctx.app_db.identity.update(**update_fields).where(id=id)

    if not isinstance(added_tag_id_list, _sentinel.Unset) and len(added_tag_id_list) > 0:
        for tag_id in added_tag_id_list:
            ctx.app_db.identity_tag.create(tag_id=tag_id, identity_id=id)
        audit_log.create(
            "identity-add-tags",
            id=id,
            added_tag_id_list=added_tag_id_list,
        )
    if not isinstance(deleted_tag_id_list, _sentinel.Unset) and len(deleted_tag_id_list) > 0:
        ctx.app_db.identity_tag.delete(identity_id=id, tag_id=deleted_tag_id_list)
        audit_log.create(
            "identity-delete-tags",
            id=id,
            deleted_tag_id_list=deleted_tag_id_list,
        )


def assign_standalone_unix_username(id: int) -> None:
    """Auto-assign the next sequential "u<hex>" unix_username to an identity.

    Only called for identities that already have a NULL unix_username, in
    "standalone" unix_mode. The sequential id is derived from the max of all
    existing "u<hex>" usernames rather than a dedicated counter table, since
    unix_username is already unique and this only runs inside a role update's
    transaction.
    """
    max_seq = 0
    for i in ctx.app_db.identity.read_all():
        if i.unix_username is None:
            continue
        m = _STANDALONE_UNIX_USERNAME_RE.match(i.unix_username)
        if m is not None:
            max_seq = max(max_seq, int(m.group(1), 16))
    username = f"u{max_seq + 1:x}"
    assert len(username) <= 8
    update(id=id, unix_username=username)
