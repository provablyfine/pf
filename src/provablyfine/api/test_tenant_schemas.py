import pathlib
import secrets
import typing

import alembic.command
import alembic.script
import cryptography.fernet
import pytest
import sqlalchemy
import sqlalchemy.exc

from . import app_db, db, migrate, registry_db

if typing.TYPE_CHECKING:
    import conftest as root_conftest

# The revision just before `bastion.tag_id_list` became nullable.
# Its upgrade reads and updates a table with Core statements, then alters it.
_BEFORE_BASTION_NULLABLE = "c8d1e4f7a2b9"


def _new_tenants(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> db.TenantDatabases:
    tenants = db.TenantDatabases(db_backend.fresh_database_url(request, tmp_path))
    request.addfinalizer(tenants.dispose)
    return tenants


def _new_tenant(tenants: db.TenantDatabases, request: pytest.FixtureRequest) -> str:
    tenant_uuid = secrets.token_hex(16)
    tenants.create(tenant_uuid)
    request.addfinalizer(lambda: tenants.delete(tenant_uuid))
    migrate.create_tenant_tables(tenants, tenant_uuid)
    return tenant_uuid


def _identity_count(tenants: db.TenantDatabases, tenant_uuid: str) -> int:
    identity = app_db.metadata.tables["identity"]
    with db.begin(tenants.engine(tenant_uuid)) as connection:
        return connection.execute(sqlalchemy.select(sqlalchemy.func.count()).select_from(identity)).scalar_one()


def test_tenants_sharing_a_server_do_not_see_each_other(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    tenants = _new_tenants(request, tmp_path, db_backend)
    first = _new_tenant(tenants, request)
    second = _new_tenant(tenants, request)

    with db.begin(tenants.engine(first), write=True) as connection:
        connection.execute(app_db.metadata.tables["identity"].insert().values(name="only-in-first", created_at=1))

    assert _identity_count(tenants, first) == 1
    assert _identity_count(tenants, second) == 0


def test_a_statement_without_a_tenant_schema_fails(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    """Nothing may fall back to a default schema, or a forgotten tenant engine would reach some tenant."""
    tenants = _new_tenants(request, tmp_path, db_backend)
    _new_tenant(tenants, request)
    # The registry's engine: on a shared server it is the one all tenants share.
    engine = db.create_engine(tenants.registry_url)
    request.addfinalizer(engine.dispose)

    with pytest.raises(sqlalchemy.exc.DBAPIError):
        with db.begin(engine) as connection:
            connection.execute(sqlalchemy.select(app_db.metadata.tables["identity"]))


def test_registry_and_tenant_tables_have_distinct_names() -> None:
    """The registry lives in the default schema. A shared name would make an unqualified tenant statement hit it."""
    assert set(app_db.metadata.tables) & set(registry_db.metadata.tables) == set()


def test_tenant_upgrade_runs_a_migration_inside_its_schema(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    tenants = _new_tenants(request, tmp_path, db_backend)
    tenant_uuid = _new_tenant(tenants, request)
    config = migrate._alembic_config("tenant", tenants.registry_url, tenant_uuid)
    alembic.command.stamp(config, _BEFORE_BASTION_NULLABLE)

    # The chain includes a migration that reads encrypted auth configs. It needs a key.
    migrate.upgrade_tenant(tenants, tenant_uuid, cryptography.fernet.Fernet.generate_key().decode())

    head = alembic.script.ScriptDirectory.from_config(config).get_current_head()
    engine = tenants.migration_engine(tenant_uuid)
    try:
        with engine.connect() as connection:
            version = connection.execute(sqlalchemy.text("SELECT version_num FROM alembic_version")).scalar_one()
    finally:
        engine.dispose()
    assert version == head
