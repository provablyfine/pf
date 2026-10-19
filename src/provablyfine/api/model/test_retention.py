import pathlib
import typing

import cryptography.fernet
import pytest

from .. import app_db, db, migrate
from ..context import ctx
from . import audit_log, audit_types, retention

if typing.TYPE_CHECKING:
    import conftest as root_conftest

DAY = retention.DAY_S
NOW = 1_000 * DAY


def _setup(request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"):
    tenants, tenant_uuid = db_backend.fresh_tenant(request, tmp_path)
    migrate.create_tenant_tables(tenants, tenant_uuid)
    return tenants.engine(tenant_uuid)


def _entry(audit_type: audit_types.AuditType, age_days: int, **details: typing.Any) -> int:
    """Write an entry and say it is `age_days` old. Returns its id."""
    audit_log.create(audit_type, **details)
    last = max(e.id for e in ctx.app_db.audit_log.read_all())
    ctx.app_db.audit_log.update(at=NOW - age_days * DAY).where(id=last)
    return last


def _ids(engine) -> set[int]:
    with db.begin(engine) as connection:
        return {e.id for e in app_db.create(connection).audit_log.read_all()}


def test_each_class_is_purged_with_its_own_period(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    engine = _setup(request, tmp_path, db_backend)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
        old_audit = _entry(audit_types.TAG_CREATE, 100, id=1, name="old", value=None)
        young_audit = _entry(audit_types.TAG_CREATE, 20, id=2, name="young", value=None)
        old_activity = _entry(audit_types.SESSION_LOGIN, 40, session_key_id="a")
        young_activity = _entry(audit_types.SESSION_LOGIN, 10, session_key_id="b")
        # The audit period is long, the activity period is short. Types are not mixed up.
        old_set = _entry(audit_types.RETENTION_SET, 900, field="audit_retention_days", old=365, new=30)

    result = retention.purge_tenant(engine, audit_retention_days=90, activity_retention_days=30, now=NOW)

    assert result.audit_entries == 1
    assert result.activity_entries == 1
    remaining = _ids(engine)
    assert {old_audit, old_activity}.isdisjoint(remaining)
    assert {young_audit, young_activity, old_set} <= remaining


def test_an_entry_exactly_at_the_cutoff_is_kept(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    engine = _setup(request, tmp_path, db_backend)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
        at_cutoff = _entry(audit_types.TAG_CREATE, 30, id=1, name="edge", value=None)

    retention.purge_tenant(engine, audit_retention_days=30, activity_retention_days=30, now=NOW)

    assert at_cutoff in _ids(engine)


def test_refs_and_names_go_with_their_entry(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    engine = _setup(request, tmp_path, db_backend)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
        _entry(audit_types.TAG_CREATE, 100, id=1, name="secret-name", value=None)
        kept = _entry(audit_types.TAG_CREATE, 1, id=2, name="kept-name", value=None)
        assert ctx.app_db.audit_log_ref.read_all(object_name="secret-name")
        assert ctx.app_db.audit_log_object_name.read_all(object_name="secret-name")

    result = retention.purge_tenant(engine, audit_retention_days=30, activity_retention_days=30, now=NOW)

    assert result.refs == 1
    assert result.object_names == 1
    with db.begin(engine) as connection:
        application_db = app_db.create(connection)
        assert application_db.audit_log_ref.read_all(object_name="secret-name") == []
        assert application_db.audit_log_object_name.read_all(object_name="secret-name") == []
        assert [r.entry_id for r in application_db.audit_log_ref.read_all(object_name="kept-name")] == [kept]


def test_ended_live_sessions_are_purged_and_running_ones_are_not(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    engine = _setup(request, tmp_path, db_backend)

    def session(session_id: str, ended_at: int | None) -> None:
        ctx.app_db.live_session.create(
            id=session_id,
            connection_id="c",
            identity_id=1,
            hostname="h",
            kind="host",
            session_id=session_id,
            started_at=NOW - 500 * DAY,
            ended_at=ended_at,
            deadline=None,
        )

    with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)):
        session("old", NOW - 40 * DAY)
        session("recent", NOW - 5 * DAY)
        session("running", None)

    result = retention.purge_tenant(engine, audit_retention_days=365, activity_retention_days=30, now=NOW)

    assert result.live_sessions == 1
    with db.begin(engine) as connection:
        assert {s.id for s in app_db.create(connection).live_session.read_all()} == {"recent", "running"}


def test_a_run_that_deletes_something_is_recorded_and_the_record_survives(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    engine = _setup(request, tmp_path, db_backend)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
        old = _entry(audit_types.TAG_CREATE, 100, id=1, name="old", value=None)

    retention.purge_tenant(engine, audit_retention_days=30, activity_retention_days=30, now=NOW)
    # Even with a period that is shorter than the age of the record, it is not purged.
    second = retention.purge_tenant(engine, audit_retention_days=30, activity_retention_days=30, now=NOW + 400 * DAY)

    assert second.total == 0
    with db.begin(engine) as connection:
        entries = app_db.create(connection).audit_log.read_all()
    assert [e.type for e in entries] == [audit_types.RETENTION_PURGE.type]
    assert entries[0].details["highest_entry_id"] == old
    assert entries[0].details["audit_entries"] == 1


def test_nothing_deleted_writes_nothing(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    engine = _setup(request, tmp_path, db_backend)

    result = retention.purge_tenant(engine, audit_retention_days=30, activity_retention_days=30, now=NOW)

    assert result.total == 0
    assert _ids(engine) == set()


def test_a_large_backlog_is_deleted_in_batches(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    engine = _setup(request, tmp_path, db_backend)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    with db.begin(engine, write=True) as connection, ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
        for i in range(7):
            _entry(audit_types.TAG_CREATE, 100, id=i, name=f"t{i}", value=None)

    result = retention.purge_tenant(engine, audit_retention_days=30, activity_retention_days=30, now=NOW, batch_size=3)

    assert result.audit_entries == 7


def test_activity_and_exempt_types_are_registered_and_disjoint() -> None:
    registered = {t.type for t in audit_types.all_types()}
    activity = {t.type for t in audit_types.ACTIVITY_TYPES}
    exempt = {t.type for t in audit_types.EXEMPT_TYPES}
    assert activity <= registered
    assert exempt <= registered
    assert activity.isdisjoint(exempt)
    assert audit_types.retention_class(audit_types.PUBLIC_KEY_DENYLISTED.type) is audit_types.RetentionClass.AUDIT
    assert audit_types.retention_class(audit_types.SESSION_LOGIN.type) is audit_types.RetentionClass.ACTIVITY
    assert audit_types.retention_class(audit_types.RETENTION_SET.type) is audit_types.RetentionClass.EXEMPT
