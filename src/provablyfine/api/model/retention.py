"""Delete the records of a tenant that are older than its retention periods.

An audit entry is deleted with its refs and with the names it introduced.
A live session is deleted once it has ended.
Entries of the exempt class are never deleted.

The work is cut into small transactions, so that a large backlog does not hold the write lock for long.
Each transaction deletes whole entries, so the database is consistent after every one.
A second run, or two runs at once, delete the same rows once.
"""

import dataclasses
import logging

import sqlalchemy

from .. import app_db, db
from ..context import ctx
from . import audit_log, audit_types

logger = logging.getLogger(__name__)

BATCH_SIZE = 5000
DAY_S = 24 * 3600


@dataclasses.dataclass
class PurgeResult:
    audit_entries: int = 0
    activity_entries: int = 0
    refs: int = 0
    object_names: int = 0
    live_sessions: int = 0
    # The highest id among the entries that were deleted. Ids of the entries that remain are not contiguous.
    highest_entry_id: int | None = None

    @property
    def total(self) -> int:
        return self.audit_entries + self.activity_entries + self.refs + self.object_names + self.live_sessions


def purge_tenant(
    engine: sqlalchemy.Engine,
    *,
    audit_retention_days: int,
    activity_retention_days: int,
    now: int,
    batch_size: int = BATCH_SIZE,
) -> PurgeResult:
    """Delete what is past its period, and record the run in the audit log if it deleted anything."""
    audit_cutoff = now - audit_retention_days * DAY_S
    activity_cutoff = now - activity_retention_days * DAY_S
    activity_types = [t.type for t in audit_types.ACTIVITY_TYPES]
    exempt_types = [t.type for t in audit_types.EXEMPT_TYPES]
    result = PurgeResult()

    while True:
        with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)):
            column = ctx.app_db.audit_log.columns
            audit = ctx.app_db.audit_log.read_page(
                column.at < audit_cutoff,
                ~column.type.in_(activity_types + exempt_types),
                order_by="id",
                descending=False,
                limit=batch_size,
            )
            activity = ctx.app_db.audit_log.read_page(
                column.at < activity_cutoff,
                column.type.in_(activity_types),
                order_by="id",
                descending=False,
                limit=batch_size,
            )
            entries = (audit + activity)[:batch_size]
            if not entries:
                break
            ids = [e.id for e in entries]
            audit_ids = {e.id for e in audit}
            result.audit_entries += sum(1 for e in entries if e.id in audit_ids)
            result.activity_entries += sum(1 for e in entries if e.id not in audit_ids)
            result.refs += ctx.app_db.audit_log_ref.delete(entry_id=ids)
            result.object_names += ctx.app_db.audit_log_object_name.delete(first_entry_id=ids)
            ctx.app_db.audit_log.delete(id=ids)
            result.highest_entry_id = max(ids + ([result.highest_entry_id] if result.highest_entry_id else []))

    while True:
        with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)):
            column = ctx.app_db.live_session.columns
            sessions = ctx.app_db.live_session.read_page(
                column.ended_at < activity_cutoff, order_by="ended_at", descending=False, limit=batch_size
            )
            if not sessions:
                break
            result.live_sessions += ctx.app_db.live_session.delete(id=[s.id for s in sessions])

    if result.total:
        with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)):
            audit_log.create(
                audit_types.TENANT_PURGE_EXPIRED,
                audit_cutoff=audit_cutoff,
                activity_cutoff=activity_cutoff,
                highest_entry_id=result.highest_entry_id,
                audit_entries=result.audit_entries,
                activity_entries=result.activity_entries,
                deleted_refs=result.refs,
                deleted_object_names=result.object_names,
                deleted_live_sessions=result.live_sessions,
            )
        logger.info(f"purged {result}")
    return result
