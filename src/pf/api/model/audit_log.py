import time

from .. import db
from ..context import ctx


def create(type, **kwargs):
    now = int(time.time())
    ctx.db.audit_log.create(
        level=db.AuditLogLevel.INFO, at=now, type=type, by_identity_id=ctx.identity_id, details=kwargs
    )


def create_warning(type, **kwargs):
    now = int(time.time())
    ctx.db.audit_log.create(
        type=type, level=db.AuditLogLevel.WARNING, at=now, by_identity_id=ctx.identity_id, details=kwargs
    )
