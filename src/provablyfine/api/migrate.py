import logging
import pathlib

import alembic.command
import alembic.config
import sqlalchemy

from . import app_db, registry_db

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
    logger.info("creating registry database")
    _create(registry_db.metadata, schema="registry", url=url)


def create_tenant(url: str) -> None:
    logger.info("creating tenant database")
    _create(app_db.metadata, schema="tenant", url=url)


def upgrade_registry(url: str) -> None:
    logger.info("upgrading registry database")
    alembic.command.upgrade(_alembic_config(schema="registry", url=url), "head")


def upgrade_tenant(url: str) -> None:
    logger.info("upgrading tenant database")
    alembic.command.upgrade(_alembic_config(schema="tenant", url=url), "head")


def is_alembic_versioned(url: str) -> bool:
    engine = sqlalchemy.create_engine(url)
    return sqlalchemy.inspect(engine).has_table("alembic_version")
