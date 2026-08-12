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


def _tables_missing_autoincrement_ddl(url: str, metadata: sqlalchemy.MetaData) -> list[str]:
    # neither compare_metadata() nor batch_alter_table see sqlite_autoincrement as it's a table construction option
    engine = sqlalchemy.create_engine(url)
    missing = []
    with engine.connect() as connection:
        for table in metadata.tables.values():
            if not table.kwargs.get("sqlite_autoincrement"):
                continue
            sql = connection.execute(
                sqlalchemy.text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = :name"),
                {"name": table.name},
            ).scalar_one()
            if "AUTOINCREMENT" not in sql:
                missing.append(table.name)
    return missing


def test_registry_autoincrement_preserved(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'registry.db'}"
    migrate.upgrade_registry(url)
    assert _tables_missing_autoincrement_ddl(url, registry_db.metadata) == []


def test_tenant_autoincrement_preserved(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'tenant.db'}"
    migrate.upgrade_tenant(url)
    assert _tables_missing_autoincrement_ddl(url, app_db.metadata) == []
