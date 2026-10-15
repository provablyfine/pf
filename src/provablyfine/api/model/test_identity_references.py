"""Deleting an identity removes the grants that name it, and only those."""

from .. import app_db
from . import audit_log, boundary, grant, identity_references, role


def _ssh(identity_id: int | None, host: str = "shell") -> grant.Grant:
    return grant.deserialize(
        {
            "type": "ssh",
            "filter": {"id": identity_id, "tag_id_list": None, "boundary_id_list": None},
            "permission": {
                "username_list": [host],
                "capability_list": ["shell"],
                "command_list": None,
                "max_session_ttl_s": None,
            },
        }
    )


def _audit(tenant_app_db: app_db.AppDb, type: str) -> list[app_db.AuditLogRow]:
    return [a for a in tenant_app_db.audit_log.read_all() if a.type == type]


def test_only_the_grants_that_name_the_identity_are_removed(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [_ssh(7), _ssh(8), _ssh(None)])

    changed = identity_references.remove(7)

    assert [o.name for o in changed] == ["ops"]
    kept = role.read_one(role_id)
    assert kept is not None
    assert [g.filter.id for g in kept.grant_list if isinstance(g, grant.SSHGrant)] == [8, None]


def test_the_update_entries_name_the_identity_and_keep_the_old_grants(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_ssh(7)])
    boundary.create("guard", "", None, [_ssh(7), _ssh(8)])

    with audit_log.cause("identity", 7, "alice", "delete"):
        identity_references.remove(7)

    role_entry, boundary_entry = (
        *_audit(tenant_app_db, "role-update-grant-list"),
        *_audit(tenant_app_db, "boundary-update-denied-list"),
    )
    for entry, old_count in ((role_entry, 1), (boundary_entry, 2)):
        assert entry.details["cause"] == {"type": "identity", "id": "7", "name": "alice", "action": "delete"}
        assert len(entry.details["old"]) == old_count
        assert entry.details["old"][0]["filter"]["id"] == 7


def test_a_ceiling_that_loses_its_last_grant_denies_everything(tenant_app_db: app_db.AppDb) -> None:
    boundary_id = boundary.create("guard", "", [_ssh(7)], [])

    identity_references.remove(7)

    remaining = boundary.read_one(id=boundary_id)
    assert remaining is not None
    # `[]` denies everything. `None` would mean "no ceiling" and would widen the boundary.
    assert remaining.ceiling_list == []


def test_a_boundary_without_a_ceiling_keeps_having_none(tenant_app_db: app_db.AppDb) -> None:
    boundary_id = boundary.create("guard", "", None, [_ssh(7)])

    identity_references.remove(7)

    remaining = boundary.read_one(id=boundary_id)
    assert remaining is not None
    assert remaining.ceiling_list is None
    assert remaining.denied_list == []


def test_nothing_changes_when_no_grant_names_the_identity(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_ssh(8)])
    boundary.create("guard", "", [_ssh(8)], [_ssh(8)])
    before = _audit(tenant_app_db, "role-update-grant-list")

    assert identity_references.remove(7) == []
    assert identity_references.find(7) == []
    assert _audit(tenant_app_db, "role-update-grant-list") == before
