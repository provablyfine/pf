"""Deleting a bastion removes the grants that name it, and only those."""

from .. import app_db
from . import audit_log, bastion, bastion_references, boundary, grant, role


def _bastion(bastion_id: int | None) -> grant.Grant:
    return grant.deserialize(
        {
            "type": "bastion",
            "filter": {"id": bastion_id},
            "permission": {"create": False, "read": True, "delete": False, "update": None},
        }
    )


def _audit(tenant_app_db: app_db.AppDb, type: str) -> list[app_db.AuditLogRow]:
    return [a for a in tenant_app_db.audit_log.read_all() if a.type == type]


def test_only_the_grants_that_name_the_bastion_are_removed(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [_bastion(7), _bastion(8), _bastion(None)])

    changed = bastion_references.remove(7)

    assert [o.name for o in changed] == ["ops"]
    kept = role.read_one(role_id)
    assert kept is not None
    assert [g.filter.id for g in kept.grant_list if isinstance(g, grant.BastionGrant)] == [8, None]


def test_the_update_entries_name_the_bastion_and_keep_the_old_grants(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://bastion.example", None, None)
    role.create("ops", "", [_bastion(bastion_id)])
    boundary.create("guard", "", None, [_bastion(bastion_id), _bastion(bastion_id + 1)])

    with audit_log.cause("bastion", bastion_id, "https://bastion.example", "delete"):
        bastion_references.remove(bastion_id)

    role_entry, boundary_entry = (
        *_audit(tenant_app_db, "role-update-grant-list"),
        *_audit(tenant_app_db, "boundary-update-denied-list"),
    )
    for entry, old_count in ((role_entry, 1), (boundary_entry, 2)):
        assert entry.details["cause"] == {
            "type": "bastion",
            "id": str(bastion_id),
            "name": "https://bastion.example",
            "action": "delete",
        }
        assert len(entry.details["old"]) == old_count
        assert entry.details["old"][0]["filter"]["id"] == bastion_id
    # Searching for the bastion finds what its deletion changed.
    found = audit_log.read_page(ref_type="bastion", ref_id=str(bastion_id))
    assert {e.type for e in found.entries} >= {"role-update-grant-list", "boundary-update-denied-list"}


def test_a_ceiling_that_loses_its_last_grant_denies_everything(tenant_app_db: app_db.AppDb) -> None:
    boundary_id = boundary.create("guard", "", [_bastion(7)], [])

    bastion_references.remove(7)

    remaining = boundary.read_one(id=boundary_id)
    assert remaining is not None
    # `[]` denies everything. `None` would mean "no ceiling" and would widen the boundary.
    assert remaining.ceiling_list == []


def test_a_boundary_without_a_ceiling_keeps_having_none(tenant_app_db: app_db.AppDb) -> None:
    boundary_id = boundary.create("guard", "", None, [_bastion(7)])

    bastion_references.remove(7)

    remaining = boundary.read_one(id=boundary_id)
    assert remaining is not None
    assert remaining.ceiling_list is None
    assert remaining.denied_list == []


def test_nothing_changes_when_no_grant_names_the_bastion(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_bastion(8)])
    boundary.create("guard", "", [_bastion(8)], [_bastion(8)])
    before = _audit(tenant_app_db, "role-update-grant-list")

    assert bastion_references.remove(7) == []
    assert bastion_references.find(7) == []
    assert _audit(tenant_app_db, "role-update-grant-list") == before
