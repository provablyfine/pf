"""Entries say which objects they are about, and can be read page by page."""

import pytest

from .. import app_db
from . import audit_log, audit_types, role


def _refs(tenant_app_db: app_db.AppDb, entry_id: int) -> set[tuple[str, str, str | None]]:
    return {
        (r.object_type, r.object_id, r.object_name) for r in tenant_app_db.audit_log_ref.read_all(entry_id=entry_id)
    }


def test_an_entry_names_the_object_it_is_about(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "the ops team", [])
    role.update(role_id, name="operations")

    entries = tenant_app_db.audit_log.read_all(type="role-update-name")

    assert [e.object_type for e in entries] == ["role"]
    assert [e.action for e in entries] == ["update-name"]
    # The update gave an id only: the name comes from the object itself. A rename also keeps the old name.
    assert ("role", str(role_id), "operations") in _refs(tenant_app_db, entries[0].id)


def test_a_deleted_object_stays_findable_by_name(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [])
    created = role.read_one(role_id)
    assert created is not None
    assert role.delete(created.id)

    page = audit_log.read_page(ref_type="role", ref_name="ops")

    assert sorted(e.type for e in page.entries) == ["role-create", "role-delete"]


def test_pages_follow_the_cursor_in_both_orders(tenant_app_db: app_db.AppDb) -> None:
    for i in range(5):
        audit_log.create(audit_types.TAG_CREATE, id=i, name=f"t{i}", value=None)

    seen: list[int] = []
    cursor = None
    while True:
        page = audit_log.read_page(descending=False, limit=2, cursor=cursor)
        seen.extend(e.id for e in page.entries)
        cursor = page.next_cursor
        if cursor is None:
            break

    assert seen == sorted(seen)
    assert len(seen) == 5

    newest = audit_log.read_page(limit=2)
    assert [e.id for e in newest.entries] == sorted(seen, reverse=True)[:2]


def test_a_cursor_from_another_order_is_refused(tenant_app_db: app_db.AppDb) -> None:
    for i in range(3):
        audit_log.create(audit_types.TAG_CREATE, id=i, name=f"t{i}", value=None)
    page = audit_log.read_page(limit=1)
    assert page.next_cursor is not None

    with pytest.raises(audit_log.InvalidCursor):
        audit_log.read_page(descending=False, cursor=page.next_cursor)
    with pytest.raises(audit_log.InvalidCursor):
        audit_log.read_page(cursor="not a cursor")


def test_filters_combine_and_take_several_values(tenant_app_db: app_db.AppDb) -> None:
    audit_log.create(audit_types.TAG_CREATE, id=1, name="a", value=None)
    audit_log.create(audit_types.TAG_DELETE, id=1, name="a", value=None)
    audit_log.create(audit_types.ROLE_CREATE, id=1, name="r")

    both = audit_log.read_page(object_type=["tag", "role"], action=["create"])
    only_tags = audit_log.read_page(object_type=["tag"], action=["create", "delete"])
    by_ref = audit_log.read_page(ref_type="tag", ref_id="1")

    assert sorted(e.type for e in both.entries) == ["role-create", "tag-create"]
    assert sorted(e.type for e in only_tags.entries) == ["tag-create", "tag-delete"]
    assert sorted(e.type for e in by_ref.entries) == ["tag-create", "tag-delete"]


def test_a_rename_keeps_the_old_value_and_is_found_under_both_names(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [])
    role.update(role_id, name="operations")

    (entry,) = tenant_app_db.audit_log.read_all(type="role-update-name")

    assert entry.details["old"] == "ops"
    assert entry.details["name"] == "operations"
    assert _refs(tenant_app_db, entry.id) == {
        ("role", str(role_id), "operations"),
        ("role", str(role_id), "ops"),
    }
    assert [e.id for e in audit_log.read_page(ref_type="role", ref_name="ops", action=["update-name"]).entries] == [
        entry.id
    ]


def test_a_repeated_warning_is_written_once(tenant_app_db: app_db.AppDb) -> None:
    """The entry is written after a rollback, so a test can only check what the dedupe lets through."""
    first = audit_log.first_in_window("session-rejected:abc:expired", 1000)
    again = audit_log.first_in_window("session-rejected:abc:expired", 1030)
    other = audit_log.first_in_window("session-rejected:abc:revoked", 1030)
    later = audit_log.first_in_window("session-rejected:abc:expired", 1061)

    assert (first, again, other, later) == (True, False, True, True)
