import base64
import collections.abc
import contextlib
import contextvars
import dataclasses
import hashlib
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
    """Name the objects now, and insert the entry at the end of the request.

    The names are the ones the objects have at this point of the request. The insert waits,
    because it takes the counter lock, which every audited request takes, and holds it until the commit.
    """
    by_identity_name = _name(audit_types.ObjectType.IDENTITY, by_identity_id) if by_identity_id is not None else None
    refs = _entry_refs(audit_type, details)

    def insert() -> None:
        db = ctx.app_db
        # The lock on this row is held until the commit. Entries are numbered in the order they commit,
        # and a request that rolls back gives its number back.
        if db.audit_log_counter.update(value=db.audit_log_counter.columns.value + 1).where(id=1) != 1:
            raise AssertionError("The audit log counter is missing")
        counter = db.audit_log_counter.read_one_for_update(id=1)
        assert counter is not None
        db.audit_log.create(
            id=counter.value,
            level=int(audit_type.level),
            at=at,
            type=audit_type.type,
            by_identity_id=by_identity_id,
            details=details,
            object_type=audit_type.object_type.value,
            action=audit_type.action.value,
            by_identity_name=by_identity_name,
        )
        for object_type, object_id, object_name in refs:
            db.audit_log_ref.create(
                entry_id=counter.value, object_type=object_type, object_id=object_id, object_name=object_name
            )

    ctx.before_commit(insert)


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
    # Where to continue. Always set, also on the last page and on an empty page.
    next_cursor: str
    # True when there was nothing after the entries of this page at the time of the query.
    is_last: bool


class InvalidCursor(Exception):
    pass


class InvalidFilter(Exception):
    pass


DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


# The cursor format is versioned. A cursor that an exporter saved must keep working after an upgrade,
# so a new format is added next to this one. Never change what version 1 means once it is released.
_CURSOR_VERSION = 1


def _encode_cursor(position: int | None, descending: bool, filter_key: str, followed_ids: list[str] | None) -> str:
    """A cursor holds the position after the last entry read. None is the start of the log.

    A read that follows a name also holds the ids that the name had on the first page.
    Every page of the read then is about the same objects.
    """
    payload: dict[str, object] = {"v": _CURSOR_VERSION, "id": position, "d": descending, "f": filter_key}
    if followed_ids is not None:
        payload["ids"] = followed_ids
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def _decode_cursor(cursor: str, descending: bool, filter_key: str) -> tuple[int | None, list[str] | None]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        data = json.loads(raw)
        version, position, cursor_descending, cursor_filter_key = data["v"], data["id"], data["d"], data["f"]
        followed_ids = data.get("ids")
    except (ValueError, KeyError, TypeError) as e:
        raise InvalidCursor("Invalid cursor") from e
    if version != _CURSOR_VERSION:
        raise InvalidCursor("Unsupported cursor version")
    if (position is not None and not isinstance(position, int)) or not isinstance(cursor_descending, bool):
        raise InvalidCursor("Invalid cursor")
    if followed_ids is not None and not (
        isinstance(followed_ids, list) and all(isinstance(i, str) for i in typing.cast(list[object], followed_ids))
    ):
        raise InvalidCursor("Invalid cursor")
    if cursor_descending != descending or cursor_filter_key != filter_key:
        raise InvalidCursor("Cursor does not match the requested order and filters")
    return position, typing.cast(list[str] | None, followed_ids)


# A name that matches more objects than this cannot be followed. The ids travel in every cursor.
MAX_FOLLOWED_OBJECTS = 100


def _objects_with_name(ref_type: audit_types.ObjectType, ref_name: str, limit: int) -> list[str]:
    """The ids of the objects that ever had this name, found in the log itself. At most `limit`."""
    ref = ctx.app_db.audit_log_ref.columns
    statement = (
        sqlalchemy.select(ref.object_id)
        .where(ref.object_type == ref_type.value, ref.object_name == ref_name)
        .distinct()
        .limit(limit)
    )
    return sorted(str(row[0]) for row in ctx.app_db.audit_log_ref.query(statement))


def _filter_key(**filters: object) -> str:
    """A short digest of the filters, so that a cursor can only continue the query it came from."""
    canonical = json.dumps(
        {
            k: sorted(typing.cast(list[str], v)) if isinstance(v, list) else v
            for k, v in filters.items()
            if v is not None
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


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
    ref_follow: bool = False,
    descending: bool = True,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> Page:
    """Read one page of entries, in `id` order, with the objects each entry is about.

    All filters apply together.
    Raises `InvalidCursor` for a cursor that is not from a query with the same order and filters.

    With `ref_follow`, `ref_name` selects the objects that ever had that name, and the entries are
    all the ones about those objects, under any of their names.
    The objects are found on the first page and travel in the cursor, so the whole read is about the same ones.
    Raises `InvalidFilter` without a `ref_type`, or when the name matches more than `MAX_FOLLOWED_OBJECTS` objects.
    """
    filter_key = _filter_key(
        level=level,
        object_type=None if object_type is None else [o.value for o in object_type],
        action=None if action is None else [a.value for a in action],
        type_prefix=type_prefix,
        by_identity_id=by_identity_id,
        start_time=start_time,
        end_time=end_time,
        ref_type=None if ref_type is None else ref_type.value,
        ref_id=ref_id,
        ref_name=ref_name,
        ref_follow=ref_follow,
    )
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
    if ref_follow and ref_name is None:
        raise InvalidFilter("ref_follow needs ref_name")
    position, followed_ids = (None, None) if cursor is None else _decode_cursor(cursor, descending, filter_key)
    if ref_follow:
        if ref_type is None or ref_name is None:
            raise InvalidFilter("Following a name needs ref_type")
        if cursor is None:
            # Every object that ever had this name. They are fixed for the whole read, whatever happens to the log.
            followed_ids = _objects_with_name(ref_type, ref_name, MAX_FOLLOWED_OBJECTS + 1)
            if len(followed_ids) > MAX_FOLLOWED_OBJECTS:
                raise InvalidFilter(
                    f"The name {ref_name!r} was used by more than {MAX_FOLLOWED_OBJECTS} {ref_type.value} objects."
                    " List them with the audit log objects command, and ask for one of them with ref_id"
                )
        elif followed_ids is None:
            raise InvalidCursor("Invalid cursor")
    if ref_type is not None or ref_id is not None or ref_name is not None:
        ref = ctx.app_db.audit_log_ref.columns
        conditions: list[typing.Any] = []
        if ref_type is not None:
            conditions.append(ref.object_type == ref_type.value)
        if ref_id is not None:
            conditions.append(ref.object_id == ref_id)
        if ref_name is not None and not ref_follow:
            conditions.append(ref.object_name == ref_name)
        if ref_follow:
            conditions.append(ref.object_id.in_(followed_ids or []))
        positional.append(col.id.in_(sqlalchemy.select(ref.entry_id).where(*conditions)))
    if position is not None:
        positional.append(col.id < position if descending else col.id > position)

    limit = max(1, min(limit, MAX_LIMIT))
    # One more row than asked tells whether there is a next page.
    rows = ctx.app_db.audit_log.read_page(*positional, order_by="id", descending=descending, limit=limit + 1, **kwargs)
    has_more = len(rows) > limit
    rows = rows[:limit]
    refs: dict[int, list[app_db.AuditLogRefRow]] = {r.id: [] for r in rows}
    if rows:
        for ref_row in ctx.app_db.audit_log_ref.read_all(entry_id=list(refs)):
            refs[ref_row.entry_id].append(ref_row)
    # With no entry, the position does not move. Reading again later continues from the same place.
    next_position = rows[-1].id if rows else position
    next_cursor = _encode_cursor(next_position, descending, filter_key, followed_ids if ref_follow else None)
    return Page(entries=rows, refs=refs, next_cursor=next_cursor, is_last=not has_more)


@dataclasses.dataclass(frozen=True)
class NamedObject:
    """An object that ever had a name, as the audit log knows it."""

    object_type: str
    object_id: str
    names: list[str]
    first_seen: int
    last_seen: int


@dataclasses.dataclass(frozen=True)
class ObjectsPage:
    objects: list[NamedObject]
    # Where to continue. Always set, as for entries.
    next_cursor: str
    is_last: bool


def _encode_objects_cursor(position: tuple[int, str] | None, descending: bool, filter_key: str) -> str:
    payload: dict[str, object] = {"v": _CURSOR_VERSION, "d": descending, "f": filter_key}
    if position is not None:
        payload["e"], payload["o"] = position
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def _decode_objects_cursor(cursor: str, descending: bool, filter_key: str) -> tuple[int, str] | None:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        version, cursor_descending, cursor_filter_key = data["v"], data["d"], data["f"]
        entry, object_id = data.get("e"), data.get("o")
    except (ValueError, KeyError, TypeError) as e:
        raise InvalidCursor("Invalid cursor") from e
    if version != _CURSOR_VERSION:
        raise InvalidCursor("Unsupported cursor version")
    if not isinstance(cursor_descending, bool):
        raise InvalidCursor("Invalid cursor")
    if cursor_descending != descending or cursor_filter_key != filter_key:
        raise InvalidCursor("Cursor does not match the requested order and filters")
    if entry is None and object_id is None:
        return None
    if not isinstance(entry, int) or not isinstance(object_id, str):
        raise InvalidCursor("Invalid cursor")
    return entry, object_id


def objects_with_name(
    ref_type: audit_types.ObjectType,
    ref_name: str,
    descending: bool = True,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> ObjectsPage:
    """One page of the objects that ever had this name, even if they were renamed or deleted since.

    They are ordered by the first entry that gave them the name, which is in commit order.
    A name can have been used by any number of objects, so the result is paged like the entries:
    the cursor holds the position and the page never grows with the number of objects.
    Each object comes with all the names it had and when the log first and last mentions it.
    The ids are the ones to give as `ref_id`.
    """
    filter_key = _filter_key(kind="objects", ref_type=ref_type.value, ref_name=ref_name)
    position = None if cursor is None else _decode_objects_cursor(cursor, descending, filter_key)
    ref = ctx.app_db.audit_log_ref.columns
    col = ctx.app_db.audit_log.columns
    limit = max(1, min(limit, MAX_LIMIT))

    # The objects of this page, in order. The first entry that gave each its name is its position.
    first_entry = sqlalchemy.func.min(ref.entry_id)
    page_query = (
        sqlalchemy.select(ref.object_id, first_entry)
        .where(ref.object_type == ref_type.value, ref.object_name == ref_name)
        .group_by(ref.object_id)
    )
    if position is not None:
        after_entry, after_id = position
        if descending:
            page_query = page_query.having(
                sqlalchemy.or_(
                    first_entry < after_entry, sqlalchemy.and_(first_entry == after_entry, ref.object_id < after_id)
                )
            )
        else:
            page_query = page_query.having(
                sqlalchemy.or_(
                    first_entry > after_entry, sqlalchemy.and_(first_entry == after_entry, ref.object_id > after_id)
                )
            )
    order = (first_entry.desc(), ref.object_id.desc()) if descending else (first_entry.asc(), ref.object_id.asc())
    # One more than asked tells whether there is a next page.
    found = [
        typing.cast(tuple[str, int], tuple(row))
        for row in ctx.app_db.audit_log_ref.query(page_query.order_by(*order).limit(limit + 1))
    ]
    is_last = len(found) <= limit
    found = found[:limit]
    next_position = (found[-1][1], found[-1][0]) if found else position
    next_cursor = _encode_objects_cursor(next_position, descending, filter_key)
    if not found:
        return ObjectsPage(objects=[], next_cursor=next_cursor, is_last=True)

    # The names and times of these objects only. The page size bounds this query.
    ids = [object_id for object_id, _ in found]
    joined = sqlalchemy.join(ref.entry_id.table, col.id.table, ref.entry_id == col.id)
    detail = (
        sqlalchemy.select(
            ref.object_id,
            ref.object_name,
            sqlalchemy.func.min(col.at),
            sqlalchemy.func.max(col.at),
            sqlalchemy.func.min(ref.entry_id),
        )
        .select_from(joined)
        .where(ref.object_type == ref_type.value, ref.object_id.in_(ids))
        .group_by(ref.object_id, ref.object_name)
    )
    # Entry ids are in commit order, so the first entry id orders names reliably, unlike the time in seconds.
    by_id: dict[str, list[tuple[str | None, int, int, int]]] = {}
    for row in ctx.app_db.audit_log_ref.query(detail):
        object_id, name, first, last, first_named = typing.cast(tuple[str, str | None, int, int, int], tuple(row))
        by_id.setdefault(object_id, []).append((name, first, last, first_named))
    objects = [
        NamedObject(
            object_type=ref_type.value,
            object_id=object_id,
            names=[name for name, _, _, _ in sorted(by_id[object_id], key=lambda r: r[3]) if name is not None],
            first_seen=min(first for _, first, _, _ in by_id[object_id]),
            last_seen=max(last for _, _, last, _ in by_id[object_id]),
        )
        for object_id in ids
    ]
    return ObjectsPage(objects=objects, next_cursor=next_cursor, is_last=is_last)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
