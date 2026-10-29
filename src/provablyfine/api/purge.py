"""Delete the activity records that are past the retention period of their tenant.

Run it from a scheduler, like `pf-api-rotate`. Once an hour is enough.
Stop scheduling it to stop deleting for every tenant.
A tenant with `retention_purge_enabled` off is skipped.
"""

import argparse
import logging
import time

from .. import log
from . import config, db, model, registry_db

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Configuration file", required=True)
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", default=None)
    args = parser.parse_args()

    conf = config.Config.load(args.config)

    log.setup_server("purge", args.debug, args.log_filename)

    tenants = db.TenantDatabases(conf.tenant_registry_url)
    registry_engine = db.create_engine(conf.tenant_registry_url)
    try:
        with registry_engine.connect() as registry_conn:
            rows = registry_db.create(registry_conn).tenant.read_all()
        for row in rows:
            if not (row.is_enabled and row.is_initialized):
                continue
            if not row.retention_purge_enabled:
                logger.warning(f"purge is disabled for tenant {row.uuid}")
                continue
            try:
                model.retention.purge_tenant(
                    tenants.engine(row.uuid),
                    audit_retention_days=row.audit_retention_days,
                    activity_retention_days=row.activity_retention_days,
                    now=int(time.time()),
                )
            except Exception:
                # One tenant must not stop the others from being purged.
                logger.exception(f"purge failed for tenant {row.uuid}")
    finally:
        tenants.dispose()
        registry_engine.dispose()
