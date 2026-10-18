"""Entries are numbered in commit order, with no holes."""

import pathlib
import threading
import time
import typing

import cryptography.fernet
import pytest

from .. import app_db, db, migrate
from ..context import ctx
from . import audit_log, audit_types

if typing.TYPE_CHECKING:
    import conftest as root_conftest


class _Rejected(Exception):
    pass


def test_a_rolled_back_request_gives_its_number_back(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    tenants, tenant_uuid = db_backend.fresh_tenant(request, tmp_path)
    migrate.create_tenant_tables(tenants, tenant_uuid)
    engine = tenants.engine(tenant_uuid)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())

    def request_writing(name: str, fail: bool) -> None:
        with db.begin(engine, write=True) as connection:
            with ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
                audit_log.create(audit_types.TAG_CREATE, id=1, name=name, value=None)
                if fail:
                    raise _Rejected()

    request_writing("first", fail=False)
    with pytest.raises(_Rejected):
        request_writing("rejected", fail=True)
    request_writing("second", fail=False)

    with db.begin(engine) as connection:
        entries = sorted(app_db.create(connection).audit_log.read_all(), key=lambda e: e.id)
    assert [(e.id, e.details["name"]) for e in entries] == [(1, "first"), (2, "second")]


def test_concurrent_requests_commit_in_the_order_of_their_numbers(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path, db_backend: "root_conftest.DbBackend"
) -> None:
    """The second request cannot take a number until the first has committed, so a lower number never commits later."""
    tenants, tenant_uuid = db_backend.fresh_tenant(request, tmp_path)
    migrate.create_tenant_tables(tenants, tenant_uuid)
    engine = tenants.engine(tenant_uuid)
    kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
    first_has_a_number = threading.Event()
    let_first_commit = threading.Event()
    commit_order: list[str] = []

    def first() -> None:
        with db.begin(engine, write=True) as connection:
            with ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
                audit_log.create(audit_types.TAG_CREATE, id=1, name="first", value=None)
                first_has_a_number.set()
                assert let_first_commit.wait(timeout=30)
        commit_order.append("first")

    def second() -> None:
        assert first_has_a_number.wait(timeout=30)
        with db.begin(engine, write=True) as connection:
            with ctx.set_app_db(app_db.create(connection)), ctx.set_kek(kek):
                audit_log.create(audit_types.TAG_CREATE, id=2, name="second", value=None)
        commit_order.append("second")

    threads = [threading.Thread(target=first), threading.Thread(target=second)]
    for thread in threads:
        thread.start()
    assert first_has_a_number.wait(timeout=30)
    # Give the second request time to reach the counter and wait there.
    time.sleep(0.5)
    assert commit_order == []
    let_first_commit.set()
    for thread in threads:
        thread.join(timeout=30)

    with db.begin(engine) as connection:
        entries = sorted(app_db.create(connection).audit_log.read_all(), key=lambda e: e.id)
    assert commit_order == ["first", "second"]
    assert [(e.id, e.details["name"]) for e in entries] == [(1, "first"), (2, "second")]
