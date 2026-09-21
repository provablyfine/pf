import time
import typing

from .. import app_db
from ..context import ctx


def create(type: str, **kwargs: typing.Any) -> None:
    now = int(time.time())
    ctx.app_db.audit_log.create(
        level=app_db.AuditLogLevel.INFO, at=now, type=type, by_identity_id=ctx.identity_id, details=kwargs
    )


def create_warning(type: str, **kwargs: typing.Any) -> None:
    now = int(time.time())
    ctx.app_db.audit_log.create(
        type=type, level=app_db.AuditLogLevel.WARNING, at=now, by_identity_id=ctx.identity_id, details=kwargs
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
