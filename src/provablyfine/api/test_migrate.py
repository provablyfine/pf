import json
import pathlib

import alembic.autogenerate
import alembic.command
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


# The revision just before the ssh grant capability model.
_BEFORE_SSH_GRANT = "5045f5101bb7"

_ANY_FILTER = {"id": None, "tag_id_list": None, "boundary_id_list": None}


def _legacy(type: str, permission: dict[str, object]) -> dict[str, object]:
    return {"type": type, "filter": _ANY_FILTER, "permission": permission}


def test_tenant_migration_upcasts_ssh_grants(tmp_path: pathlib.Path) -> None:
    url = f"sqlite:///{tmp_path / 'tenant.db'}"
    config = migrate._alembic_config(schema="tenant", url=url)
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
    engine = sqlalchemy.create_engine(url)
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

    migrate.upgrade_tenant(url)

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
    url = f"sqlite:///{tmp_path / 'tenant.db'}"
    config = migrate._alembic_config(schema="tenant", url=url)
    alembic.command.upgrade(config, _BEFORE_MAX_SESSION_TTL)

    tag_grant = {"type": "tag", "filter": {"id": None}, "permission": {"create": True, "read": True, "delete": True}}
    three_key = {"username_list": ["root"], "capability_list": ["shell"], "command_list": []}
    engine = sqlalchemy.create_engine(url)
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

    migrate.upgrade_tenant(url)

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


def _tables_missing_autoincrement_ddl(url: str, metadata: sqlalchemy.MetaData) -> list[str]:
    """Find tables declared with sqlite_autoincrement=True whose live DDL lacks AUTOINCREMENT.

    compare_metadata() cannot see this: sqlite_autoincrement is a dialect-level table
    construction option, not a column/constraint/index difference, so a batch_alter_table
    rebuild that forgets to re-pass it produces a schema that still diffs clean.
    """
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
