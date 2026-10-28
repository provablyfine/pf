import base64
import collections.abc
import contextlib
import contextvars
import dataclasses
import hashlib
import json
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


@dataclasses.dataclass(frozen=True)
class ForeignAuthor:
    """An author who belongs to another tenant than the one that holds the entry.

    The identity id of such an author means nothing in this tenant, so only its name is kept.
    The tenant id is the stable key. The names are what they were when the entry was written.
    """

    tenant_id: int
    tenant_name: str
    identity_name: str | None


_foreign_author_var: contextvars.ContextVar[ForeignAuthor | None] = contextvars.ContextVar(
    "audit_foreign_author", default=None
)


def caller_as_foreign_author(tenant_name: str) -> ForeignAuthor:
    """Describe the caller, so that its entries can be written in the database of another tenant.

    Call it while the caller's own tenant is still the current one, because it reads the identity name.
    """
    identity_id = ctx.identity_id
    identity_name = _name(audit_types.ObjectType.IDENTITY, identity_id) if identity_id is not None else None
    return ForeignAuthor(tenant_id=ctx.tenant_id, tenant_name=tenant_name, identity_name=identity_name)


@contextlib.contextmanager
def written_by(author: ForeignAuthor) -> collections.abc.Generator[None]:
    """Attribute the entries written inside the block to an author of another tenant.

    Use it inside `ctx.in_other_tenant`, where the caller's identity id means nothing.
    """
    token = _foreign_author_var.set(author)
    try:
        yield
    finally:
        _foreign_author_var.reset(token)


_cause_var: contextvars.ContextVar[dict[str, typing.Any] | None] = contextvars.ContextVar("audit_cause", default=None)


@contextlib.contextmanager
def cause(
    object_type: audit_types.ObjectType, object_id: int | str, name: str | None, action: audit_types.Action
) -> collections.abc.Generator[None]:
    """Say that the entries written inside the block happen because of `action` on this object."""
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
    _write(audit_type, now, by_identity_id, {**details, **extra}, _foreign_author_var.get())


def create_after_rollback(audit_type: audit_types.AuditType, **details: typing.Any) -> None:
    """Record an entry about a request that is about to be rejected. Call it right before raising.

    Rejecting a request rolls its transaction back, and a plain `create` with it.
    This one is written in its own transaction, after the rollback.
    """
    now = int(time.time())
    by_identity_id = ctx.identity_id

    foreign_author = _foreign_author_var.get()

    def write() -> None:
        _write(audit_type, now, by_identity_id, details, foreign_author)

    ctx.after_rollback(write)


def _write(
    audit_type: audit_types.AuditType,
    at: int,
    by_identity_id: int | None,
    details: dict[str, typing.Any],
    foreign_author: ForeignAuthor | None,
) -> None:
    """Name the objects now, and insert the entry at the end of the request.

    The names are the ones the objects have at this point of the request. The insert waits,
    because it takes the counter lock, which every audited request takes, and holds it until the commit.
    """
    if foreign_author is not None:
        assert by_identity_id is None, "An author of another tenant has no identity id here"
        by_identity_name = foreign_author.identity_name
    else:
        by_identity_name = (
            _name(audit_types.ObjectType.IDENTITY, by_identity_id) if by_identity_id is not None else None
        )
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
            by_tenant_id=None if foreign_author is None else foreign_author.tenant_id,
            by_tenant_name=None if foreign_author is None else foreign_author.tenant_name,
        )
        for ref in refs:
            db.audit_log_ref.create(
                entry_id=counter.value, object_type=ref.object_type, object_id=ref.object_id, object_name=ref.name
            )
            if ref.names_object and ref.name is not None:
                # A rename back to an earlier name, or to the same name, is rejected by the unique key.
                db.audit_log_object_name.create_if_absent(
                    object_type=ref.object_type,
                    object_id=ref.object_id,
                    object_name=ref.name,
                    first_entry_id=counter.value,
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


@dataclasses.dataclass(frozen=True)
class _Ref:
    object_type: str
    object_id: str
    name: str | None
    # The entry gives the object this name. A ref that only mentions the object does not.
    names_object: bool = False


def _entry_refs(audit_type: audit_types.AuditType, details: dict[str, typing.Any]) -> list[_Ref]:
    """Every object the entry is about, once each: the target first, then the objects it names."""
    found: dict[tuple[str, str], str | None] = {}
    named: set[tuple[str, str]] = set()
    extra: list[_Ref] = []
    target_id = None if audit_type.target_key is None else _text(details, audit_type.target_key)
    if target_id is not None:
        carried = _text(details, "name") or _text(details, "url")
        found[(audit_type.object_type.value, target_id)] = carried or _name(audit_type.object_type, target_id)
        if audit_type.names_object and carried is not None:
            named.add((audit_type.object_type.value, target_id))
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
        extra.append(_Ref(audit_type.object_type.value, target_id, old_name))
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
    return [
        _Ref(object_type, object_id, name, (object_type, object_id) in named)
        for (object_type, object_id), name in found.items()
    ] + extra


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
    """The ids of the objects that ever had this name. At most `limit`."""
    rows = ctx.app_db.audit_log_object_name.read_page(
        object_type=ref_type.value, object_name=ref_name, order_by="id", descending=False, limit=limit
    )
    return sorted(r.object_id for r in rows)


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
    by_tenant_id: int | None = None,
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
        by_tenant_id=by_tenant_id,
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
    if by_tenant_id is not None:
        kwargs["by_tenant_id"] = by_tenant_id
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
    # Every name it had, in the order it got them.
    names: list[str]
    # When the entry that gave it its first name was written. None once that entry is gone.
    first_seen: int | None


@dataclasses.dataclass(frozen=True)
class ObjectsPage:
    objects: list[NamedObject]
    # Where to continue. Always set, as for entries.
    next_cursor: str
    is_last: bool


def _encode_objects_cursor(position: int | None, descending: bool, filter_key: str) -> str:
    payload: dict[str, object] = {"v": _CURSOR_VERSION, "d": descending, "f": filter_key}
    if position is not None:
        payload["e"] = position
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")


def _decode_objects_cursor(cursor: str, descending: bool, filter_key: str) -> int | None:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        version, cursor_descending, cursor_filter_key = data["v"], data["d"], data["f"]
        position = data.get("e")
    except (ValueError, KeyError, TypeError) as e:
        raise InvalidCursor("Invalid cursor") from e
    if version != _CURSOR_VERSION:
        raise InvalidCursor("Unsupported cursor version")
    if not isinstance(cursor_descending, bool):
        raise InvalidCursor("Invalid cursor")
    if cursor_descending != descending or cursor_filter_key != filter_key:
        raise InvalidCursor("Cursor does not match the requested order and filters")
    if position is not None and not isinstance(position, int):
        raise InvalidCursor("Invalid cursor")
    return position


def objects_with_name(
    ref_type: audit_types.ObjectType,
    ref_name: str,
    descending: bool = True,
    limit: int = DEFAULT_LIMIT,
    cursor: str | None = None,
) -> ObjectsPage:
    """One page of the objects that ever had this name, even if they were renamed or deleted since.

    They are ordered by when they got the name, which is the order of the rows, and the rows are in commit order.
    A name can have been used by any number of objects, so the result is paged like the entries:
    the cursor holds the position and the page never grows with the number of objects.
    Each object comes with all the names it had.
    The ids are the ones to give as `ref_id`.
    """
    filter_key = _filter_key(kind="objects", ref_type=ref_type.value, ref_name=ref_name)
    position = None if cursor is None else _decode_objects_cursor(cursor, descending, filter_key)
    table = ctx.app_db.audit_log_object_name
    after: list[typing.Any] = []
    if position is not None:
        after.append(table.columns.id < position if descending else table.columns.id > position)
    limit = max(1, min(limit, MAX_LIMIT))

    # One more than asked tells whether there is a next page.
    rows = table.read_page(
        *after, object_type=ref_type.value, object_name=ref_name, order_by="id", descending=descending, limit=limit + 1
    )
    is_last = len(rows) <= limit
    rows = rows[:limit]
    next_cursor = _encode_objects_cursor(rows[-1].id if rows else position, descending, filter_key)
    if not rows:
        return ObjectsPage(objects=[], next_cursor=next_cursor, is_last=True)

    # Every name of these objects. The page size bounds this query.
    names: dict[str, list[app_db.AuditLogObjectNameRow]] = {}
    for named in sorted(
        table.read_all(object_type=ref_type.value, object_id=[r.object_id for r in rows]), key=lambda n: n.id
    ):
        names.setdefault(named.object_id, []).append(named)
    first_entries = {n[0].first_entry_id for n in names.values()}
    at = {e.id: e.at for e in ctx.app_db.audit_log.read_all(id=sorted(first_entries))}
    objects = [
        NamedObject(
            object_type=ref_type.value,
            object_id=r.object_id,
            names=[n.object_name for n in names[r.object_id]],
            first_seen=at.get(names[r.object_id][0].first_entry_id),
        )
        for r in rows
    ]
    return ObjectsPage(objects=objects, next_cursor=next_cursor, is_last=is_last)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
