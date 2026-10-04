import logging
import pathlib
import threading

import alembic.command
import alembic.config
import sqlalchemy

from . import app_db, db, registry_db

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = pathlib.Path(__file__).parent / "migrations"

# Alembic keeps the state of a running command in module globals, so two commands in one
# process must not overlap. Requests that create tenants run in threads.
# On sqlite the registry write lock already serialized them. Postgres and MySQL do not.
_ALEMBIC_LOCK = threading.Lock()


def _alembic_config(
    scripts: str, registry_url: str, tenant_uuid: str | None = None, kek: str | None = None
) -> alembic.config.Config:
    """`scripts` names the migration directory. `tenant_uuid` names the tenant to migrate, if any.

    `kek` is the Fernet key that encrypts tenant config blobs. A migration that reads a
    config needs it, and refuses to run without it.
    """
    cfg = alembic.config.Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR / scripts))
    cfg.set_main_option("sqlalchemy.url", registry_url)
    if tenant_uuid is not None:
        cfg.set_main_option("pf.tenant_uuid", tenant_uuid)
    if kek is not None:
        cfg.set_main_option("pf.kek", kek)
    return cfg


def _stamp_head(scripts: str, registry_url: str, tenant_uuid: str | None = None) -> None:
    with _ALEMBIC_LOCK:
        alembic.command.stamp(_alembic_config(scripts, registry_url, tenant_uuid), "head")


def create_registry(url: str) -> None:
    logger.info("creating registry database")
    engine = db.create_engine(url)
    try:
        with db.begin(engine, write=True) as conn:
            registry_db.metadata.create_all(conn)
    finally:
        engine.dispose()
    _stamp_head("registry", url)


def create_tenant_tables(tenants: db.TenantDatabases, tenant_uuid: str) -> None:
    """Create the tables of a tenant that `tenants.create` made."""
    logger.info("creating tenant tables")
    with db.begin(tenants.engine(tenant_uuid), write=True) as conn:
        app_db.metadata.create_all(conn)
    _stamp_head("tenant", tenants.registry_url, tenant_uuid)


def upgrade_registry(url: str) -> None:
    logger.info("upgrading registry database")
    with _ALEMBIC_LOCK:
        alembic.command.upgrade(_alembic_config("registry", url), "head")


def upgrade_tenant(tenants: db.TenantDatabases, tenant_uuid: str, kek: str) -> None:
    """Upgrade one tenant to head. `kek` is the Fernet key that encrypts its config columns.

    A migration that looks inside a stored config has to decrypt it, so it cannot run without the key.
    """
    logger.info("upgrading tenant tables")
    with _ALEMBIC_LOCK:
        alembic.command.upgrade(_alembic_config("tenant", tenants.registry_url, tenant_uuid, kek), "head")


def is_alembic_versioned(url: str) -> bool:
    engine = db.create_engine(url)
    try:
        return sqlalchemy.inspect(engine).has_table("alembic_version")
    finally:
        engine.dispose()
