import time
import typing

from .. import app_db, orm
from ..context import ctx
from . import grant


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


def create(type: str, refs: dict[str, typing.Any] | None = None, **kwargs: typing.Any) -> None:
    now = int(time.time())
    details = kwargs if not refs else {**kwargs, "refs": refs}
    ctx.app_db.audit_log.create(
        level=app_db.AuditLogLevel.INFO, at=now, type=type, by_identity_id=ctx.identity_id, details=details
    )


def create_warning(type: str, refs: dict[str, typing.Any] | None = None, **kwargs: typing.Any) -> None:
    now = int(time.time())
    details = kwargs if not refs else {**kwargs, "refs": refs}
    ctx.app_db.audit_log.create(
        type=type, level=app_db.AuditLogLevel.WARNING, at=now, by_identity_id=ctx.identity_id, details=details
    )


def create_warning_after_rollback(type: str, **kwargs: typing.Any) -> None:
    """Record a warning about a request that is about to be rejected. Call it right before raising.

    Rejecting a request rolls its transaction back, and a plain `create_warning` with it.
    This one is written in its own transaction, after the rollback.
    """
    now = int(time.time())
    by_identity_id = ctx.identity_id

    def write() -> None:
        ctx.app_db.audit_log.create(
            type=type, level=app_db.AuditLogLevel.WARNING, at=now, by_identity_id=by_identity_id, details=kwargs
        )

    ctx.after_rollback(write)


def read_all(
    level: int | None = None,
    object_type: str | None = None,
    by_identity_id: str | None = None,
    start_time: int | None = None,
    end_time: int | None = None,
) -> list[app_db.AuditLogRow]:
    positional: list[typing.Any] = []
    kwargs: dict[str, typing.Any] = {}
    col = ctx.app_db.audit_log.columns
    if start_time is not None:
        positional.append(col.at >= start_time)
    if end_time is not None:
        positional.append(col.at <= end_time)
    if object_type is not None:
        positional.append(col.type.like(f"{object_type}%"))
    if level is not None:
        kwargs["level"] = level
    if by_identity_id is not None:
        kwargs["by_identity_id"] = by_identity_id
    return ctx.app_db.audit_log.read_all(*positional, **kwargs)
