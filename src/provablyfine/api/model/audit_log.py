import base64
import collections.abc
import contextlib
import contextvars
import dataclasses
import json
import threading
import time
import typing

import sqlalchemy

from .. import app_db, orm
from ..context import ctx
from . import audit_types, grant


def refs(
    grants: typing.Iterable[grant.Grant] = (),
    tags: typing.Iterable[int] = (),
    identities: typing.Iterable[int] = (),
    roles: typing.Iterable[int] = (),
    boundaries: typing.Iterable[int] = (),
    bastions: typing.Iterable[int] = (),
    auths: typing.Iterable[int] = (),
) -> dict[str, dict[str, dict[str, typing.Any] | None]]:
    """Name the objects an audit entry points to, as they are now.

    Ids stay in the entry. This adds what a reader needs once the object is renamed or gone.
    Call it before the delete, in the same transaction as the entry.
    An id that does not exist is recorded as None. Writing an entry must not fail a request.

    Tenant ids are not resolved. Tenants live in the registry, not in the tenant database.
    """
    found = grant.referenced_ids(grants)
    db = ctx.app_db
    result = {
        "tag": _resolve(db.tag, found.tag | set(tags), lambda r: {"name": r.name, "value": r.value}),
        "identity": _resolve(
            db.identity, found.identity | set(identities), lambda r: {"name": r.name, "unix_username": r.unix_username}
        ),
        "role": _resolve(db.role, found.role | set(roles), lambda r: {"name": r.name}),
        "boundary": _resolve(db.boundary, found.boundary | set(boundaries), lambda r: {"name": r.name}),
        "bastion": _resolve(db.bastion, found.bastion | set(bastions), lambda r: {"url": r.url}),
        "auth": _resolve(db.auth, found.auth | set(auths), lambda r: {"name": r.name}),
    }
    return {kind: ids for kind, ids in result.items() if ids}


def _resolve[R: typing.NamedTuple](
    table: orm.Table[R], ids: set[int], label: typing.Callable[[R], dict[str, typing.Any]]
) -> dict[str, dict[str, typing.Any] | None]:
    if not ids:
        return {}
    labels = {typing.cast(int, getattr(row, "id")): label(row) for row in table.read_all(id=sorted(ids))}
    return {str(i): labels.get(i) for i in sorted(ids)}


_cause_var: contextvars.ContextVar[dict[str, typing.Any] | None] = contextvars.ContextVar("audit_cause", default=None)


@contextlib.contextmanager
def cause(
    object_type: audit_types.ObjectType, object_id: int | str, name: str | None, action: audit_types.Action
) -> collections.abc.Generator[None]:
    """Say that the entries written inside the block happen because of `action` on this object.

    Deleting a bastion rewrites the roles that name it. Those entries name the bastion as their cause.
    """
    token = _cause_var.set({"type": object_type.value, "id": str(object_id), "name": name, "action": action.value})
    try:
        yield
    finally:
        _cause_var.reset(token)


def create(audit_type: audit_types.AuditType, refs: dict[str, typing.Any] | None = None, **details: typing.Any) -> None:
    """Write an entry about `audit_type`.

    `details` is stored as given. The key named by `audit_type.target_key` holds the id of the object
    the entry is about. `refs` comes from `refs()` and names the other objects the entry mentions.
    """
    now = int(time.time())
    by_identity_id = ctx.identity_id
    extra: dict[str, typing.Any] = {}
    if refs:
        extra["refs"] = refs
    current_cause = _cause_var.get()
    if current_cause is not None:
        extra["cause"] = current_cause
    _write(audit_type, now, by_identity_id, {**details, **extra})


_DEDUPE_SECONDS = 60
_DEDUPE_MAX_KEYS = 4096
_dedupe_lock = threading.Lock()
_dedupe_seen: dict[str, int] = {}


def first_in_window(key: str, now: int) -> bool:
    """True if `key` was not seen in the last minute. The table never grows past `_DEDUPE_MAX_KEYS`."""
    with _dedupe_lock:
        last = _dedupe_seen.get(key)
        if last is not None and now - last < _DEDUPE_SECONDS:
            return False
        if len(_dedupe_seen) >= _DEDUPE_MAX_KEYS:
            for stale in [k for k, t in _dedupe_seen.items() if now - t >= _DEDUPE_SECONDS]:
                del _dedupe_seen[stale]
            if len(_dedupe_seen) >= _DEDUPE_MAX_KEYS:
                _dedupe_seen.clear()
        _dedupe_seen[key] = now
        return True


def create_after_rollback(
    audit_type: audit_types.AuditType, dedupe_key: str | None = None, **details: typing.Any
) -> None:
    """Record an entry about a request that is about to be rejected. Call it right before raising.

    Rejecting a request rolls its transaction back, and a plain `create` with it.
    This one is written in its own transaction, after the rollback.

    With a `dedupe_key`, the entry is written at most once a minute for that key, per server process.
    A client that retries a rejected request in a loop cannot fill the log with it.
    """
    now = int(time.time())
    if dedupe_key is not None and not first_in_window(f"{audit_type.type}:{dedupe_key}", now):
        return
    by_identity_id = ctx.identity_id

    def write() -> None:
        _write(audit_type, now, by_identity_id, details)

    ctx.after_rollback(write)


def _write(
    audit_type: audit_types.AuditType, at: int, by_identity_id: int | None, details: dict[str, typing.Any]
) -> None:
    db = ctx.app_db
    by_identity_name = _name(audit_types.ObjectType.IDENTITY, by_identity_id) if by_identity_id is not None else None
    entry_id = db.audit_log.create(
        level=int(audit_type.level),
        at=at,
        type=audit_type.type,
        by_identity_id=by_identity_id,
        details=details,
        object_type=audit_type.object_type.value,
        action=audit_type.action.value,
        by_identity_name=by_identity_name,
    )
    assert entry_id is not None
    for object_type, object_id, object_name in _entry_refs(audit_type, details):
        db.audit_log_ref.create(
            entry_id=entry_id, object_type=object_type, object_id=object_id, object_name=object_name
        )


_NAMED_TABLES = {
    audit_types.ObjectType.IDENTITY: ("identity", "name"),
    audit_types.ObjectType.ROLE: ("role", "name"),
    audit_types.ObjectType.BOUNDARY: ("boundary", "name"),
    audit_types.ObjectType.TAG: ("tag", "name"),
    audit_types.ObjectType.BASTION: ("bastion", "url"),
    audit_types.ObjectType.AUTH: ("auth", "name"),
}


def _name(object_type: audit_types.ObjectType, object_id: int | str) -> str | None:
    """The name an object has now, or None if it is gone or has none."""
    named = _NAMED_TABLES.get(object_type)
    if named is None:
        return None
    try:
        key = int(object_id)
    except ValueError:
        return None
    row = getattr(ctx.app_db, named[0]).read_one(id=key)
    return None if row is None else getattr(row, named[1])


def _text(details: dict[str, typing.Any], key: str) -> str | None:
    value: object = details.get(key)
    return None if value is None else str(value)


def _entry_refs(audit_type: audit_types.AuditType, details: dict[str, typing.Any]) -> list[tuple[str, str, str | None]]:
    """Every object the entry is about, once each: the target first, then the objects it names."""
    found: dict[tuple[str, str], str | None] = {}
    extra: list[tuple[str, str, str | None]] = []
    target_id = None if audit_type.target_key is None else _text(details, audit_type.target_key)
    if target_id is not None:
        name = _text(details, "name") or _text(details, "url") or _name(audit_type.object_type, target_id)
        found[(audit_type.object_type.value, target_id)] = name
    # A cascade names the object whose deletion caused it.
    cause_details: dict[str, typing.Any] | None = details.get("cause")
    if cause_details is not None:
        found.setdefault(
            (str(cause_details["type"]), str(cause_details["id"])),
            None if cause_details.get("name") is None else str(cause_details["name"]),
        )
    # A rename is found under the old name as well as the new one.
    old_name = _text(details, "old")
    if target_id is not None and audit_type.action == audit_types.Action.UPDATE_NAME and old_name is not None:
        extra.append((audit_type.object_type.value, target_id, old_name))
    # A cascade says which role or boundary it rewrote.
    owner_type, owner_id = _text(details, "owner_type"), _text(details, "owner_id")
    if owner_type is not None and owner_id is not None:
        found.setdefault((owner_type, owner_id), _text(details, "owner_name"))
    # Entries about a session or an invitation say whose it is.
    identity_id = _text(details, "identity_id")
    if identity_id is not None:
        found.setdefault(
            (audit_types.ObjectType.IDENTITY.value, identity_id), _name(audit_types.ObjectType.IDENTITY, identity_id)
        )
    # A certificate says which host it is for.
    host_id = _text(details, "host_id")
    if host_id is not None:
        found.setdefault((audit_types.ObjectType.IDENTITY.value, host_id), _text(details, "hostname"))
    refs: dict[str, dict[str, dict[str, typing.Any] | None]] = details.get("refs") or {}
    for kind, by_id in refs.items():
        for object_id, label in by_id.items():
            name = None if label is None else _text(label, "name") or _text(label, "url")
            found.setdefault((kind, str(object_id)), name)
    return [(object_type, object_id, name) for (object_type, object_id), name in found.items()] + extra


@dataclasses.dataclass(frozen=True)
class Page:
    entries: list[app_db.AuditLogRow]
    refs: dict[int, list[app_db.AuditLogRefRow]]
    next_cursor: str | None


class InvalidCursor(Exception):
    pass


DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


def _encode_cursor(last_id: int, descending: bool) -> str:
    raw = json.dumps({"id": last_id, "d": descending}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str, descending: bool) -> int:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        data = json.loads(raw)
        last_id, cursor_descending = data["id"], data["d"]
    except (ValueError, KeyError, TypeError) as e:
        raise InvalidCursor("Invalid cursor") from e
    if not isinstance(last_id, int) or cursor_descending != descending:
        raise InvalidCursor("Cursor does not match the requested order")
    return last_id


def read_page(
    level: int | None = None,
    object_type: list[audit_types.ObjectType] | None = None,
    action: list[audit_types.Action] | None = None,
    type_prefix: str | None = None,
    by_identity_id: str | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
    ref_type: audit_types.ObjectType | None = None,
    ref_id: str | None = None,
    ref_name: str | None = None,
    descending: bool = True,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> Page:
    """Read one page of entries, in `id` order, with the objects each entry is about.

    All filters apply together. Raises `InvalidCursor` for a cursor that is not from the same order.
    """
    positional: list[typing.Any] = []
    kwargs: dict[str, typing.Any] = {}
    col = ctx.app_db.audit_log.columns
    if start_time is not None:
        positional.append(col.at >= start_time)
    if end_time is not None:
        positional.append(col.at <= end_time)
    if type_prefix is not None:
        positional.append(col.type.like(f"{_escape_like(type_prefix)}%", escape="\\"))
    if object_type:
        kwargs["object_type"] = [o.value for o in object_type]
    if action:
        kwargs["action"] = [a.value for a in action]
    if level is not None:
        kwargs["level"] = level
    if by_identity_id is not None:
        kwargs["by_identity_id"] = by_identity_id
    if ref_type is not None or ref_id is not None or ref_name is not None:
        ref = ctx.app_db.audit_log_ref.columns
        conditions: list[typing.Any] = []
        if ref_type is not None:
            conditions.append(ref.object_type == ref_type.value)
        if ref_id is not None:
            conditions.append(ref.object_id == ref_id)
        if ref_name is not None:
            conditions.append(ref.object_name == ref_name)
        positional.append(col.id.in_(sqlalchemy.select(ref.entry_id).where(*conditions)))
    if cursor is not None:
        last_id = _decode_cursor(cursor, descending)
        positional.append(col.id < last_id if descending else col.id > last_id)

    limit = max(1, min(limit, MAX_LIMIT))
    # One more row than asked tells whether there is a next page.
    rows = ctx.app_db.audit_log.read_page(*positional, order_by="id", descending=descending, limit=limit + 1, **kwargs)
    has_more = len(rows) > limit
    rows = rows[:limit]
    refs: dict[int, list[app_db.AuditLogRefRow]] = {r.id: [] for r in rows}
    if rows:
        for ref_row in ctx.app_db.audit_log_ref.read_all(entry_id=list(refs)):
            refs[ref_row.entry_id].append(ref_row)
    next_cursor = _encode_cursor(rows[-1].id, descending) if has_more else None
    return Page(entries=rows, refs=refs, next_cursor=next_cursor)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
