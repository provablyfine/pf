"""Audit entries name the objects their grants point to, as they were when the entry was written."""

from .. import app_db
from . import grant, role


def _tag_grant(tag_id: int) -> grant.Grant:
    return grant.IdentityGrant(
        filter=grant.TripletFilter(tag_id_list=[tag_id]),
        permission=grant.IdentityPermission(
            create=None,
            read=True,
            update=None,
            delete=False,
            add_tag_id_list=None,
            del_tag_id_list=None,
            invite_list=None,
        ),
    )


def _details(tenant_app_db: app_db.AppDb, type: str) -> list[dict[str, object]]:
    return [a.details for a in tenant_app_db.audit_log.read_all() if a.type == type]


def test_role_entries_keep_the_tag_name_after_the_tag_is_gone(tenant_app_db: app_db.AppDb) -> None:
    tag_id = tenant_app_db.tag.create(name="env", value="prod")
    assert tag_id is not None
    role_id = role.create("ops", "", [_tag_grant(tag_id)])
    tenant_app_db.tag.delete(id=tag_id)

    [created] = _details(tenant_app_db, "role-create")
    assert created["refs"] == {"tag": {str(tag_id): {"name": "env", "value": "prod"}}}

    stored = role.read_one(role_id)
    assert stored is not None
    assert role.delete(stored.id)
    [deleted] = _details(tenant_app_db, "role-delete")
    assert deleted["refs"] == {"tag": {str(tag_id): None}}


def test_an_entry_without_references_has_no_refs_key(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [])
    [created] = _details(tenant_app_db, "role-create")
    assert "refs" not in created
