import time

from ..context import ctx

def create(type, **kwargs):
    now = int(time.time())
    ctx.db.audit_log.create(
        type=type,
        at=now,
        by=ctx.identity_id,
        detail=kwargs
    )

