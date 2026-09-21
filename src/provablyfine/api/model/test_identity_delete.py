"""What deleting an identity leaves in the audit log."""

import time

from .. import app_db
from . import boundary, identity


def _delete_entry(tenant_app_db: app_db.AppDb) -> dict[str, object]:
    entries = [a for a in tenant_app_db.audit_log.read_all() if a.type == "identity-delete"]
    assert len(entries) == 1
    return entries[0].details


def _identity() -> int:
    boundary_id = boundary.create("guard", "", None, [])
    return identity.create("alice", [boundary_id], [], unix_username="al")


def _session(tenant_app_db: app_db.AppDb, identity_id: int, name: str, **overrides: object) -> None:
    now = int(time.time())
    row: dict[str, object] = dict(
        id=name,
        public_key={},
        identity_id=identity_id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
        expires_at=now + 3600,
        login_ip="10.0.0.1",
        role_id=None,
        logged_out_at=None,
    )
    tenant_app_db.identity_session_key.create(**{**row, **overrides})


def test_the_audit_entry_says_who_was_deleted(tenant_app_db: app_db.AppDb) -> None:
    identity_id = _identity()

    identity.delete(identity_id)

    details = _delete_entry(tenant_app_db)
    assert details["id"] == identity_id
    assert details["name"] == "alice"
    assert details["unix_username"] == "al"
    assert details["boundary_id_list"] == [1]
    assert tenant_app_db.identity.read_one(id=identity_id) is None


def test_live_sessions_are_listed_and_the_others_are_only_counted(tenant_app_db: app_db.AppDb) -> None:
    identity_id = _identity()
    now = int(time.time())
    _session(tenant_app_db, identity_id, "live")
    _session(tenant_app_db, identity_id, "expired", expires_at=now - 10)
    _session(tenant_app_db, identity_id, "revoked", is_revoked=True, revoked_at=now)
    _session(tenant_app_db, identity_id, "logged-out", logged_out_at=now)

    identity.delete(identity_id)

    details = _delete_entry(tenant_app_db)
    assert details["session_count"] == 4
    assert [s["id"] for s in details["live_sessions"]] == ["live"]  # type: ignore[index]
    assert details["live_sessions"][0]["login_ip"] == "10.0.0.1"  # type: ignore[index]
    assert tenant_app_db.identity_session_key.read_all(identity_id=identity_id) == []


def test_the_list_of_live_sessions_is_capped(tenant_app_db: app_db.AppDb) -> None:
    identity_id = _identity()
    for i in range(identity._AUDIT_LIVE_SESSIONS + 5):
        _session(tenant_app_db, identity_id, f"live-{i}")

    identity.delete(identity_id)

    details = _delete_entry(tenant_app_db)
    assert len(details["live_sessions"]) == identity._AUDIT_LIVE_SESSIONS  # type: ignore[arg-type]
    assert details["live_sessions_truncated"] == 5


def test_certificates_that_are_still_valid_are_listed(tenant_app_db: app_db.AppDb) -> None:
    identity_id = _identity()
    now = int(time.time())
    tenant_app_db.ssh_connection.create(
        connection_id="valid", identity_id=identity_id, hostname="web", deadline=now + 60, valid_before=now + 60
    )
    tenant_app_db.ssh_connection.create(
        connection_id="old", identity_id=identity_id, hostname="web", deadline=None, valid_before=now - 60
    )

    identity.delete(identity_id)

    details = _delete_entry(tenant_app_db)
    assert [c["connection_id"] for c in details["valid_ssh_connections"]] == ["valid"]  # type: ignore[attr-defined,index]
    assert tenant_app_db.ssh_connection.read_all(identity_id=identity_id) == []


def test_key_material_never_reaches_the_audit_log(tenant_app_db: app_db.AppDb) -> None:
    identity_id = _identity()
    tenant_app_db.identity_invitation_key.create(
        id="invitation",
        key=b"secret-key-material",
        identity_id=identity_id,
        created_at=0,
        revoked_at=None,
        accepted_at=None,
        expires_at=2**31,
        is_revoked=False,
        is_accepted=False,
        accepted_public_key_id=None,
    )

    identity.delete(identity_id)

    details = _delete_entry(tenant_app_db)
    assert [i["id"] for i in details["pending_invitations"]] == ["invitation"]  # type: ignore[attr-defined,index]
    assert "secret-key-material" not in str(details)
