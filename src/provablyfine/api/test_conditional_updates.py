"""The conditional statements that keep concurrent requests correct.

Under one write lock the races cannot happen, so these tests check the statements themselves.
A statement that changes no row must say so, whatever the database.
"""

import pytest

from .. import jwk
from . import app_db, context, model, responses
from .context import ctx


def _signing_key_id(tenant_app_db: app_db.AppDb) -> int:
    model.signing_key.create(app_db.SigningKeyType.USER, jwk.KeyType.ED25519, valid_after=0, valid_before=2**31)
    row = tenant_app_db.signing_key.read_one()
    assert row is not None
    return row.id


def test_serial_numbers_are_handed_out_in_consecutive_ranges(tenant_app_db: app_db.AppDb) -> None:
    key_id = _signing_key_id(tenant_app_db)

    assert model.signing_key.allocate_serial_numbers(key_id, 3) == 1
    assert model.signing_key.allocate_serial_numbers(key_id, 2) == 4
    assert model.signing_key.allocate_serial_numbers(key_id, 0) == 6
    assert model.signing_key.allocate_serial_numbers(key_id, 1) == 6
    row = tenant_app_db.signing_key.read_one(id=key_id)
    assert row is not None
    assert row.serial_number == 7


def test_update_that_expects_an_old_value_applies_once(tenant_app_db: app_db.AppDb) -> None:
    key_id = _signing_key_id(tenant_app_db)
    table = tenant_app_db.signing_key

    assert table.update(serial_number=2).where(id=key_id, serial_number=1) == 1
    assert table.update(serial_number=2).where(id=key_id, serial_number=1) == 0


def test_session_role_can_only_be_set_once(tenant_app_db: app_db.AppDb) -> None:
    sessions = tenant_app_db.identity_session_key
    sessions.create(
        id="session",
        public_key={},
        identity_id=1,
        created_at=0,
        is_revoked=False,
        revoked_at=None,
        expires_at=2**31,
        login_ip=None,
        role_id=None,
        logged_out_at=None,
    )

    assert sessions.update(role_id=5).where(id="session", role_id=None) == 1
    assert sessions.update(role_id=6).where(id="session", role_id=None) == 0
    row = sessions.read_one(id="session")
    assert row is not None
    assert row.role_id == 5


def test_create_if_absent_lets_the_loser_know(tenant_app_db: app_db.AppDb) -> None:
    """The insert that loses a unique-constraint race returns False instead of raising.

    A plain uncaught IntegrityError would leave the transaction unusable on Postgres, which
    aborts it after any error. The connection must still work afterwards, whatever the database.
    """
    table = tenant_app_db.public_key_denylist
    assert table.create_if_absent(id="key", key_id="key", created_at=0) is True
    assert table.create_if_absent(id="key", key_id="key", created_at=1) is False

    assert len(table.read_all(id="key")) == 1
    # The connection is still usable: a statement after the rejected insert must not fail too.
    assert table.read_one(id="key") is not None


def test_denying_a_key_twice_is_not_an_error(tenant_app_db: app_db.AppDb) -> None:
    model.denylist.create("key", identity_invitation_id="invitation")
    model.denylist.create("key", identity_invitation_id="invitation")

    assert len(tenant_app_db.public_key_denylist.read_all(key_id="key")) == 1
    audit = [a for a in tenant_app_db.audit_log.read_all() if a.type == "denylist-add"]
    assert len(audit) == 2


def test_refusing_a_denied_key_leaves_its_audit_entry_for_after_the_rollback(tenant_app_db: app_db.AppDb) -> None:
    model.denylist.create("key")
    deferred = context.Deferred()
    with ctx.set_deferred(deferred):
        with pytest.raises(responses.ProblemHTTPException):
            model.denylist.enforce_not_denied("key")

    # Nothing is written in the request's own transaction, which is about to roll back.
    assert not [a for a in tenant_app_db.audit_log.read_all() if a.type == "denylist-check-failed"]
    assert len(deferred.after_rollback) == 1
    deferred.after_rollback[0]()
    assert len([a for a in tenant_app_db.audit_log.read_all() if a.type == "denylist-check-failed"]) == 1
