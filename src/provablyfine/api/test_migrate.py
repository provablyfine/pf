import json
import pathlib
import typing

import alembic.autogenerate
import alembic.command
import alembic.runtime.migration
import cryptography.fernet
import pytest
import sqlalchemy

from . import app_db, db, migrate, registry_db

if typing.TYPE_CHECKING:
    import conftest as root_conftest


_TENANT = "0" * 32

# Migrations that read encrypted columns are handed this key. Tests that store a row write
# it with the same key.
_KEK = cryptography.fernet.Fernet.generate_key().decode()


def _sqlite_tenant(tmp_path: pathlib.Path) -> db.TenantDatabases:
    """A tenant on sqlite, whose file is next to a registry file in `tmp_path`."""
    tenants = db.TenantDatabases(f"sqlite:///{tmp_path / 'registry.db'}")
    tenants.create(_TENANT)
    return tenants


def _diffs(engine: sqlalchemy.Engine, metadata: sqlalchemy.MetaData) -> list[object]:
    with engine.connect() as connection:
        context = alembic.runtime.migration.MigrationContext.configure(connection, opts={"compare_type": True})
        return alembic.autogenerate.compare_metadata(context, metadata)


def test_registry_migrations_match_model(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'registry.db'}"
    migrate.upgrade_registry(url)
    assert _diffs(sqlalchemy.create_engine(url), registry_db.metadata) == []


def test_tenant_migrations_match_model(tmp_path: pathlib.Path) -> None:
    tenants = _sqlite_tenant(tmp_path)
    migrate.upgrade_tenant(tenants, _TENANT, _KEK)
    assert _diffs(tenants.migration_engine(_TENANT), app_db.metadata) == []


def test_registry_creation_matches_model(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    """create_registry, on every backend, must produce exactly the live model's schema.

    Unlike test_registry_migrations_match_model, this does not replay the historical
    migration chain: that chain predates multi-backend support and its early revisions
    hardcode column types (e.g. unbounded VARCHAR) that assume SQLite, so it isn't
    portable. create_registry (metadata.create_all, then stamp to head) is what
    app.py and endpoints/tenant.py actually call to provision a brand-new database on
    any backend; that is the path this test exercises.
    """
    url = db_backend.fresh_database_url(request, tmp_path)
    migrate.create_registry(url)
    assert _diffs(sqlalchemy.create_engine(url), registry_db.metadata) == []


def test_tenant_creation_matches_model(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    """Like test_registry_creation_matches_model, for a new tenant database."""
    tenants, tenant_uuid = db_backend.fresh_tenant(request, tmp_path)
    migrate.create_tenant_tables(tenants, tenant_uuid)
    assert _diffs(tenants.migration_engine(tenant_uuid), app_db.metadata) == []


# The revision just before the ssh grant capability model.
_BEFORE_SSH_GRANT = "5045f5101bb7"

_ANY_FILTER = {"id": None, "tag_id_list": None, "boundary_id_list": None}


def _legacy(type: str, permission: dict[str, object]) -> dict[str, object]:
    return {"type": type, "filter": _ANY_FILTER, "permission": permission}


def test_tenant_migration_upcasts_ssh_grants(tmp_path: pathlib.Path) -> None:
    tenants = _sqlite_tenant(tmp_path)
    config = migrate._alembic_config("tenant", tenants.registry_url, _TENANT)
    alembic.command.upgrade(config, _BEFORE_SSH_GRANT)

    tag_grant = {"type": "tag", "filter": {"id": None}, "permission": {"create": True, "read": True, "delete": True}}
    role_grants = [
        tag_grant,
        _legacy("ssh-shell", {"username_list": ["root"], "permit_agent_forwarding": True}),
        # Both forwarding bools, and the shape where they are absent entirely
        # (they were schema defaults, so old rows may omit them).
        _legacy("ssh-shell", {"username_list": ["alice"], "permit_x11_forwarding": True}),
        _legacy("ssh-shell", {"username_list": ["bob"]}),
        _legacy("ssh-port-forwarding", {"username_list": ["root"]}),
        _legacy("ssh-command", {"username_list": ["root"], "command_list": ["/bin/ls"]}),
        # Denotes no atoms at all: the migration drops it.
        _legacy("ssh-command", {"username_list": ["root"], "command_list": []}),
    ]
    engine = tenants.engine(_TENANT)
    with engine.begin() as connection:
        connection.execute(
            sqlalchemy.text("INSERT INTO role (id, name, description, grant_list) VALUES (1, 'r', '', :g)"),
            {"g": json.dumps(role_grants)},
        )
        connection.execute(
            sqlalchemy.text(
                "INSERT INTO boundary (id, name, description, ceiling_list, denied_list) VALUES (1, 'b', '', :c, :d)"
            ),
            {
                "c": json.dumps([_legacy("ssh-shell", {"username_list": ["root"]})]),
                "d": json.dumps([_legacy("ssh-shell", {"username_list": ["alice"]})]),
            },
        )
        # A boundary with no ceiling at all must keep its null.
        connection.execute(
            sqlalchemy.text(
                "INSERT INTO boundary (id, name, description, ceiling_list, denied_list) VALUES (2, 'c', '', NULL, :d)"
            ),
            {"d": json.dumps([])},
        )

    migrate.upgrade_tenant(tenants, _TENANT, _KEK)

    with engine.connect() as connection:
        grant_list = json.loads(connection.execute(sqlalchemy.text("SELECT grant_list FROM role")).scalar_one())
        ceiling, denied = connection.execute(
            sqlalchemy.text("SELECT ceiling_list, denied_list FROM boundary WHERE id = 1")
        ).one()
        empty_ceiling = connection.execute(
            sqlalchemy.text("SELECT ceiling_list FROM boundary WHERE id = 2")
        ).scalar_one()

    # The no-atom ssh-command entry is gone; the non-SSH grant is untouched.
    assert [g["type"] for g in grant_list] == ["tag", "ssh", "ssh", "ssh", "ssh", "ssh"]
    assert grant_list[0] == tag_grant
    # Four keys, not three: the later max_session_ttl_s migration runs too.
    assert grant_list[1]["permission"] == {
        "username_list": ["root"],
        "capability_list": ["shell", "pty", "user-rc", "agent-forwarding"],
        "command_list": [],
        "max_session_ttl_s": None,
    }
    assert grant_list[2]["permission"]["capability_list"] == ["shell", "pty", "user-rc", "x11-forwarding"]
    assert grant_list[3]["permission"]["capability_list"] == ["shell", "pty", "user-rc"]
    assert grant_list[4]["permission"]["capability_list"] == ["port-forwarding"]
    assert grant_list[5]["permission"] == {
        "username_list": ["root"],
        "capability_list": [],
        "command_list": ["/bin/ls"],
        "max_session_ttl_s": None,
    }
    assert [g["type"] for g in json.loads(ceiling)] == ["ssh"]
    assert [g["type"] for g in json.loads(denied)] == ["ssh"]
    assert empty_ceiling is None


# The revision just before max_session_ttl_s was added to the ssh grant.
_BEFORE_MAX_SESSION_TTL = "c4d7e9b21a35"


def _ssh(permission: dict[str, object]) -> dict[str, object]:
    return {"type": "ssh", "filter": _ANY_FILTER, "permission": permission}


def test_tenant_migration_adds_max_session_ttl(tmp_path: pathlib.Path) -> None:
    tenants = _sqlite_tenant(tmp_path)
    config = migrate._alembic_config("tenant", tenants.registry_url, _TENANT)
    alembic.command.upgrade(config, _BEFORE_MAX_SESSION_TTL)

    tag_grant = {"type": "tag", "filter": {"id": None}, "permission": {"create": True, "read": True, "delete": True}}
    three_key = {"username_list": ["root"], "capability_list": ["shell"], "command_list": []}
    engine = tenants.engine(_TENANT)
    with engine.begin() as connection:
        connection.execute(
            sqlalchemy.text("INSERT INTO role (id, name, description, grant_list) VALUES (1, 'r', '', :g)"),
            {"g": json.dumps([tag_grant, _ssh(three_key)])},
        )
        connection.execute(
            sqlalchemy.text(
                "INSERT INTO boundary (id, name, description, ceiling_list, denied_list) VALUES (1, 'b', '', :c, :d)"
            ),
            {"c": json.dumps([_ssh(three_key)]), "d": json.dumps([_ssh(three_key)])},
        )
        # A boundary with no ceiling at all must keep its null.
        connection.execute(
            sqlalchemy.text(
                "INSERT INTO boundary (id, name, description, ceiling_list, denied_list) VALUES (2, 'c', '', NULL, :d)"
            ),
            {"d": json.dumps([])},
        )

    migrate.upgrade_tenant(tenants, _TENANT, _KEK)

    with engine.connect() as connection:
        grant_list = json.loads(connection.execute(sqlalchemy.text("SELECT grant_list FROM role")).scalar_one())
        ceiling, denied = connection.execute(
            sqlalchemy.text("SELECT ceiling_list, denied_list FROM boundary WHERE id = 1")
        ).one()
        empty_ceiling = connection.execute(
            sqlalchemy.text("SELECT ceiling_list FROM boundary WHERE id = 2")
        ).scalar_one()

    # null is the whole axis: unbounded, which is what these grants already
    # meant before the field existed.
    expected = {**three_key, "max_session_ttl_s": None}
    assert grant_list[0] == tag_grant  # non-ssh grants are untouched
    assert grant_list[1]["permission"] == expected
    assert json.loads(ceiling)[0]["permission"] == expected
    assert json.loads(denied)[0]["permission"] == expected
    assert empty_ceiling is None


def _tables_missing_autoincrement_ddl(engine: sqlalchemy.Engine, metadata: sqlalchemy.MetaData) -> list[str]:
    """Find tables declared with sqlite_autoincrement=True whose live DDL lacks AUTOINCREMENT.

    compare_metadata() cannot see this: sqlite_autoincrement is a dialect-level table
    construction option, not a column/constraint/index difference, so a batch_alter_table
    rebuild that forgets to re-pass it produces a schema that still diffs clean.
    """
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
    assert _tables_missing_autoincrement_ddl(sqlalchemy.create_engine(url), registry_db.metadata) == []


def test_tenant_autoincrement_preserved(tmp_path: pathlib.Path) -> None:
    tenants = _sqlite_tenant(tmp_path)
    migrate.upgrade_tenant(tenants, _TENANT, _KEK)
    assert _tables_missing_autoincrement_ddl(tenants.engine(_TENANT), app_db.metadata) == []


def test_registry_migration_backfills_tenant_uuid(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'registry.db'}"
    config = migrate._alembic_config("registry", url)
    alembic.command.upgrade(config, "6356a7f48b37")

    engine = sqlalchemy.create_engine(url)
    with engine.begin() as connection:
        for tenant_id, name in ((1, "root"), (2, "acme"), (3, "beta")):
            connection.execute(
                sqlalchemy.text(
                    "INSERT INTO tenant (id, name, display_name, owner_id, database_url, is_enabled,"
                    " is_initialized, is_deleted, created_at) VALUES (:id, :n, :n, NULL, 'sqlite://', 1, 1, 0, 0)"
                ),
                {"id": tenant_id, "n": name},
            )

    migrate.upgrade_registry(url)

    with engine.connect() as connection:
        uuids = dict(connection.execute(sqlalchemy.text("SELECT name, uuid FROM tenant")).all())
    assert uuids["root"] == registry_db.ROOT_TENANT_UUID
    assert len({uuids["acme"], uuids["beta"], uuids["root"]}) == 3


def test_tenant_migration_nulls_out_unrestricted_bastions(tmp_path: pathlib.Path) -> None:
    """A bastion with `tag_id_list is None` is visible to every identity.

    Existing bastions stored with `[]` are rewritten to `NULL` so they keep that
    visibility across the upgrade. A bastion with a non-empty tag_id_list is
    left untouched.
    """
    tenants = _sqlite_tenant(tmp_path)
    config = migrate._alembic_config("tenant", tenants.registry_url, _TENANT)
    alembic.command.upgrade(config, "c8d1e4f7a2b9")

    engine = tenants.engine(_TENANT)
    with engine.begin() as connection:
        connection.execute(
            sqlalchemy.text(
                "INSERT INTO bastion (id, url, ssh_proxy_jump, tag_id_list, created_at, created_by_id)"
                " VALUES (1, 'https://unrestricted', NULL, '[]', 0, NULL)"
            )
        )
        connection.execute(
            sqlalchemy.text(
                "INSERT INTO bastion (id, url, ssh_proxy_jump, tag_id_list, created_at, created_by_id)"
                " VALUES (2, 'https://tagged', NULL, '[1, 2]', 0, NULL)"
            )
        )

    migrate.upgrade_tenant(tenants, _TENANT, _KEK)

    with engine.connect() as connection:
        tag_id_lists = dict(
            connection.execute(sqlalchemy.text("SELECT url, tag_id_list FROM bastion ORDER BY id")).all()
        )
    assert json.loads(tag_id_lists["https://unrestricted"]) is None
    assert json.loads(tag_id_lists["https://tagged"]) == [1, 2]


# The revision just before `auth.type` split oidc-device-code into two types.
_BEFORE_DEVICE_CODE_SPLIT = "736d98eea63f"


def test_tenant_migration_splits_secret_device_code_auths(tmp_path: pathlib.Path) -> None:
    """An oidc-device-code config that carries a client_secret becomes an oidc-secret-device-code one.

    A config without a secret keeps its type. Only the type column is touched: the secret
    was already inside the encrypted config, where it stays.
    """
    tenants = _sqlite_tenant(tmp_path)
    config = migrate._alembic_config("tenant", tenants.registry_url, _TENANT)
    alembic.command.upgrade(config, _BEFORE_DEVICE_CODE_SPLIT)

    kek = cryptography.fernet.Fernet(_KEK)
    issuer_and_client = {"issuer": "https://issuer", "client_id": "cid"}
    rows = [
        (1, "oidc-device-code", dict(issuer_and_client)),
        (2, "oidc-device-code", {**issuer_and_client, "client_secret": "s"}),
        (3, "oidc-device-code", {**issuer_and_client, "client_secret": ""}),
        (4, "oidc", {**issuer_and_client, "client_secret": "s"}),
    ]

    engine = tenants.engine(_TENANT)
    with engine.begin() as connection:
        for row_id, auth_type, stored_config in rows:
            connection.execute(
                sqlalchemy.text(
                    "INSERT INTO auth (id, name, client_type, description, created_at, is_enabled, type, config)"
                    " VALUES (:id, :n, 'cli', '', 0, 1, :t, :c)"
                ),
                {
                    "id": row_id,
                    "n": f"auth{row_id}",
                    "t": auth_type,
                    "c": kek.encrypt(json.dumps(stored_config).encode()),
                },
            )

    migrate.upgrade_tenant(tenants, _TENANT, _KEK)

    with engine.connect() as connection:
        types = dict(connection.execute(sqlalchemy.text("SELECT id, type FROM auth ORDER BY id")).all())
        stored = connection.execute(sqlalchemy.text("SELECT config FROM auth WHERE id = 2")).scalar_one()
    assert types == {
        1: "oidc-device-code",
        2: "oidc-secret-device-code",
        3: "oidc-device-code",
        4: "oidc",
    }
    assert json.loads(kek.decrypt(stored)) == {**issuer_and_client, "client_secret": "s"}


def test_tenant_migration_without_a_kek_fails(tmp_path: pathlib.Path) -> None:
    """The split reads encrypted configs, so a chain that reaches it without a key stops."""
    tenants = _sqlite_tenant(tmp_path)
    config = migrate._alembic_config("tenant", tenants.registry_url, _TENANT)
    with pytest.raises(RuntimeError, match=r"pf\.kek"):
        alembic.command.upgrade(config, "head")


def test_registry_migration_drops_unique_tenant_name(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'registry.db'}"
    migrate.upgrade_registry(url)

    engine = sqlalchemy.create_engine(url)
    with engine.begin() as connection:
        for tenant_id in (1, 2):
            connection.execute(
                sqlalchemy.text(
                    "INSERT INTO tenant (id, uuid, name, display_name, owner_id, database_url, is_enabled,"
                    " is_initialized, is_deleted, created_at) VALUES (:id, :u, 'acme', 'Acme', NULL, 'sqlite://',"
                    " 1, 1, 0, 0)"
                ),
                {"id": tenant_id, "u": f"uuid-{tenant_id}"},
            )
    with engine.connect() as connection:
        assert connection.execute(sqlalchemy.text("SELECT count(*) FROM tenant")).scalar_one() == 2
