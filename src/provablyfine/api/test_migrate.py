import pathlib

import alembic.autogenerate
import alembic.runtime.migration
import sqlalchemy

from . import app_db, migrate, registry_db


def _diffs(url: str, metadata: sqlalchemy.MetaData) -> list[object]:
    engine = sqlalchemy.create_engine(url)
    with engine.connect() as connection:
        context = alembic.runtime.migration.MigrationContext.configure(connection, opts={"compare_type": True})
        return alembic.autogenerate.compare_metadata(context, metadata)


def test_registry_migrations_match_model(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'registry.db'}"
    migrate.upgrade_registry(url)
    assert _diffs(url, registry_db.metadata) == []


def test_tenant_migrations_match_model(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'tenant.db'}"
    migrate.upgrade_tenant(url)
    assert _diffs(url, app_db.metadata) == []
