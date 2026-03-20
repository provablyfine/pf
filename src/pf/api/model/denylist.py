import time

from .. import responses
from ..context import ctx
from . import audit_log


def create(key_id, **kwargs):
    now = int(time.time())
    ctx.db.public_key_denylist.create(key_id=key_id, created_at=now)
    audit_log.create_warning(type="denylist-add", public_key_id=key_id, **kwargs)


def enforce_not_denied(key_id):
    # is the requesting public key in a global denylist ?
    denylist_entry = ctx.db.public_key_denylist.read_one(key_id=key_id)
    if denylist_entry:
        audit_log.create_warning(type="denylist-check-failed", public_key_id=key_id)
        # Purposedly return an error that is not very clear
        # because the client is probably malevolent
        raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Unable to use key"))
