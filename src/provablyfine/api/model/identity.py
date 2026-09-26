import dataclasses
import time
import typing

from ... import _sentinel
from ..context import ctx
from . import audit_log, utils

# The identity that `initialize` creates for the first administrator of a tenant.
FOUNDING_ID = 1


@dataclasses.dataclass(frozen=True)
class Identity:
    id: int
    name: str
    tag_id_list: list[int]
    boundary_id_list: list[int]
    unix_username: str | None


def create(name: str, boundary_id_list: list[int], tag_id_list: list[int], unix_username: str | None = None) -> int:
    now = int(time.time())
    identity_id = ctx.app_db.identity.create(name=name, created_at=now, unix_username=unix_username)
    assert identity_id is not None
    for boundary_id in boundary_id_list:
        ctx.app_db.identity_boundary.create(identity_id=identity_id, boundary_id=boundary_id)
    for tag_id in tag_id_list:
        ctx.app_db.identity_tag.create(tag_id=tag_id, identity_id=identity_id)
    audit_log.create(
        "identity-create",
        id=identity_id,
        name=name,
        boundary_id_list=boundary_id_list,
        tag_id_list=tag_id_list,
        unix_username=unix_username,
    )
    return identity_id


# Sessions that are still usable when an identity is deleted are listed one by one in the audit log.
# A busy identity can have many, so the list is capped.
_AUDIT_LIVE_SESSIONS = 50


def _deletion_snapshot(identity: Identity) -> dict[str, typing.Any]:
    """What the deletion destroys, for the audit log. Never includes key material."""
    now = int(time.time())
    app = ctx.app_db

    sessions = app.identity_session_key.read_all(identity_id=identity.id)
    live = [s for s in sessions if not s.is_revoked and s.logged_out_at is None and s.expires_at > now]
    live.sort(key=lambda s: s.created_at, reverse=True)
    invitations = app.identity_invitation_key.read_all(identity_id=identity.id)
    connections = app.ssh_connection.read_all(identity_id=identity.id)

    return {
        "name": identity.name,
        "unix_username": identity.unix_username,
        "tag_id_list": identity.tag_id_list,
        "boundary_id_list": identity.boundary_id_list,
        "role_id_list": sorted(m.role_id for m in app.role_member.read_all(identity_id=identity.id)),
        "account_keys": [
            {"id": k.id, "is_revoked": k.is_revoked} for k in app.identity_account_key.read_all(identity_id=identity.id)
        ],
        "pending_invitations": [
            {"id": i.id, "expires_at": i.expires_at}
            for i in invitations
            if not i.is_accepted and not i.is_revoked and i.expires_at > now
        ],
        "session_count": len(sessions),
        "last_session_created_at": max((s.created_at for s in sessions), default=None),
        "live_sessions": [
            {
                "id": s.id,
                "created_at": s.created_at,
                "expires_at": s.expires_at,
                "login_ip": s.login_ip,
                "role_id": s.role_id,
            }
            for s in live[:_AUDIT_LIVE_SESSIONS]
        ],
        "live_sessions_truncated": max(0, len(live) - _AUDIT_LIVE_SESSIONS),
        # Certificates that were already issued stay valid until they expire. They cannot be revoked.
        "valid_ssh_connections": [
            {
                "connection_id": c.connection_id,
                "hostname": c.hostname,
                "deadline": c.deadline,
                "valid_before": c.valid_before,
            }
            for c in connections
            if c.valid_before > now
        ],
    }


def delete(id: int) -> None:
    """Delete an identity, and everything that only makes sense with it.

    Its keys and sessions go at once: the next request signed with one of them is a 401.
    The audit entry keeps what is lost with them (see `_deletion_snapshot`).
    The grants that name the identity are removed by `identity_references.remove`. Call it first.

    Certificates that were already issued cannot be revoked. They stay valid until they expire,
    and an SSH session that is already open runs until its deadline.
    """
    identity = read_one(id=id)
    assert identity is not None
    snapshot = _deletion_snapshot(identity)
    ctx.app_db.identity_boundary.delete(identity_id=id)
    ctx.app_db.identity_tag.delete(identity_id=id)
    ctx.app_db.identity_account_key.delete(identity_id=id)
    ctx.app_db.identity_session_key.delete(identity_id=id)
    ctx.app_db.identity_invitation_key.delete(identity_id=id)
    ctx.app_db.role_member.delete(identity_id=id)
    ctx.app_db.ssh_connection.delete(identity_id=id)
    ctx.app_db.identity.delete(id=id)
    audit_log.create("identity-delete", id=id, **snapshot)


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
    unix_username: str | _sentinel.Unset | None = _sentinel.UNSET,
) -> None:
    update_fields: dict[str, typing.Any] = {}
    if not isinstance(name, _sentinel.Unset):
        audit_log.create(
            "identity-update-name",
            id=id,
            name=name,
        )
        update_fields["name"] = name
    if not isinstance(unix_username, _sentinel.Unset):
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
