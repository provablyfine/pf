import logging
import pathlib

import alembic.command
import alembic.config
import sqlalchemy

from . import app_db, config, registry_db

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = pathlib.Path(__file__).parent / "migrations"


def _alembic_config(schema: str, url: str) -> alembic.config.Config:
    cfg = alembic.config.Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR / schema))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _create(metadata: sqlalchemy.MetaData, schema: str, url: str) -> None:
    engine = sqlalchemy.create_engine(url)
    metadata.create_all(engine)
    alembic.command.stamp(_alembic_config(schema=schema, url=url), "head")


def create_registry(url: str) -> None:
    _create(registry_db.metadata, schema="registry", url=url)


def create_tenant(url: str) -> None:
    _create(app_db.metadata, schema="tenant", url=url)


def upgrade_registry(url: str) -> None:
    alembic.command.upgrade(_alembic_config(schema="registry", url=url), "head")


def upgrade_tenant(url: str) -> None:
    alembic.command.upgrade(_alembic_config(schema="tenant", url=url), "head")


def upgrade_all(conf: config.Config) -> None:
    logger.info("upgrading registry database")
    upgrade_registry(conf.tenant_registry_url)

    registry_engine = sqlalchemy.create_engine(conf.tenant_registry_url)
    with registry_engine.connect() as connection:
        tenants = registry_db.create(connection).tenant.read_all()

    for tenant_row in tenants:
        if tenant_row.is_deleted:
            continue
        logger.info(f"upgrading tenant {tenant_row.name}")
        try:
            upgrade_tenant(tenant_row.database_url)
        except Exception as exception:
            logger.exception(f"failed to upgrade tenant {tenant_row.name}")
            raise exception
