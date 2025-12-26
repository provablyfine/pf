import time

from .. import db
from ..context import ctx


def create(type, **kwargs):
    now = int(time.time())
    ctx.db.audit_log.create(
        type=type,
        level=db.AuditLogLevel.INFO,
        at=now,
        by=ctx.identity_id,
        detail=kwargs
    )


def create_warning(type, **kwargs):
    now = int(time.time())
    ctx.db.audit_log.create(
        type=type,
        level=db.AuditLogLevel.WARNING,
        at=now,
        by=ctx.identity_id,
        detail=kwargs
    )
