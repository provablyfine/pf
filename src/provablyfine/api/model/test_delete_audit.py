"""Deleting a role or a boundary leaves what it contained in the audit log."""

from .. import app_db
from . import boundary, role


def _entries(tenant_app_db: app_db.AppDb, type: str) -> list[dict[str, object]]:
    return [a.details for a in tenant_app_db.audit_log.read_all() if a.type == type]


def test_role_delete_keeps_the_role_in_the_audit_log(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "the ops team", [])

    role.delete(role_id)

    assert tenant_app_db.role.read_one(id=role_id) is None
    assert _entries(tenant_app_db, "role-delete") == [
        {"id": role_id, "name": "ops", "description": "the ops team", "grant_list": []}
    ]


def test_boundary_delete_keeps_a_missing_ceiling_as_none(tenant_app_db: app_db.AppDb) -> None:
    boundary_id = boundary.create("guard", "a guard", None, [])

    boundary.delete(boundary_id)

    assert tenant_app_db.boundary.read_one(id=boundary_id) is None
    assert _entries(tenant_app_db, "boundary-delete") == [
        {"id": boundary_id, "name": "guard", "description": "a guard", "ceiling_list": None, "denied_list": []}
    ]
