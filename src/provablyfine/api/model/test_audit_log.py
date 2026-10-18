"""Entries say which objects they are about, and can be read page by page."""

import base64
import json

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

    page = audit_log.read_page(ref_type=audit_types.ObjectType.ROLE, ref_name="ops")

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
        if page.is_last:
            break

    assert seen == sorted(seen)
    assert len(seen) == 5

    newest = audit_log.read_page(limit=2)
    assert [e.id for e in newest.entries] == sorted(seen, reverse=True)[:2]


def test_a_cursor_from_other_filters_is_refused(tenant_app_db: app_db.AppDb) -> None:
    for i in range(3):
        audit_log.create(audit_types.TAG_CREATE, id=i, name="t", value=None)
    page = audit_log.read_page(ref_type=audit_types.ObjectType.TAG, ref_name="t", limit=1)
    assert not page.is_last

    # The same query continues. Another filter, or following the name, is another query.
    audit_log.read_page(ref_type=audit_types.ObjectType.TAG, ref_name="t", limit=1, cursor=page.next_cursor)
    tag = audit_types.ObjectType.TAG
    with pytest.raises(audit_log.InvalidCursor):
        audit_log.read_page(ref_type=tag, ref_name="t", ref_follow=True, limit=1, cursor=page.next_cursor)
    with pytest.raises(audit_log.InvalidCursor):
        audit_log.read_page(ref_type=tag, ref_name="other", limit=1, cursor=page.next_cursor)
    with pytest.raises(audit_log.InvalidCursor):
        audit_log.read_page(level=1, limit=1, cursor=page.next_cursor)


def test_following_a_name_finds_an_object_under_its_old_and_new_names(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [])
    role.update(role_id, name="operations")
    role.update(role_id, description="the ops team")
    role.create("unrelated", "", [])

    plain = audit_log.read_page(ref_type=audit_types.ObjectType.ROLE, ref_name="ops")
    followed = audit_log.read_page(ref_type=audit_types.ObjectType.ROLE, ref_name="ops", ref_follow=True)
    by_new_name = audit_log.read_page(ref_type=audit_types.ObjectType.ROLE, ref_name="operations", ref_follow=True)

    assert sorted(e.type for e in plain.entries) == ["role-create", "role-update-name"]
    assert sorted(e.type for e in followed.entries) == [
        "role-create",
        "role-update-description",
        "role-update-name",
    ]
    assert [e.id for e in by_new_name.entries] == [e.id for e in followed.entries]
    assert {r.object_id for refs in followed.refs.values() for r in refs} == {str(role_id)}


def test_following_a_name_finds_a_deleted_object(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [])
    role.update(role_id, name="operations")
    created = role.read_one(role_id)
    assert created is not None
    assert role.delete(created.id)

    followed = audit_log.read_page(ref_type=audit_types.ObjectType.ROLE, ref_name="ops", ref_follow=True)

    assert sorted(e.type for e in followed.entries) == ["role-create", "role-delete", "role-update-name"]


def test_following_needs_a_name_and_a_type(tenant_app_db: app_db.AppDb) -> None:
    with pytest.raises(audit_log.InvalidFilter):
        audit_log.read_page(ref_follow=True)
    with pytest.raises(audit_log.InvalidFilter):
        audit_log.read_page(ref_name="ops", ref_follow=True)


def test_a_cursor_from_another_order_is_refused(tenant_app_db: app_db.AppDb) -> None:
    for i in range(3):
        audit_log.create(audit_types.TAG_CREATE, id=i, name=f"t{i}", value=None)
    page = audit_log.read_page(limit=1)

    with pytest.raises(audit_log.InvalidCursor):
        audit_log.read_page(descending=False, cursor=page.next_cursor)
    with pytest.raises(audit_log.InvalidCursor):
        audit_log.read_page(cursor="not a cursor")


def test_filters_combine_and_take_several_values(tenant_app_db: app_db.AppDb) -> None:
    audit_log.create(audit_types.TAG_CREATE, id=1, name="a", value=None)
    audit_log.create(audit_types.TAG_DELETE, id=1, name="a", value=None)
    audit_log.create(audit_types.ROLE_CREATE, id=1, name="r")

    both = audit_log.read_page(
        object_type=[audit_types.ObjectType.TAG, audit_types.ObjectType.ROLE], action=[audit_types.Action.CREATE]
    )
    only_tags = audit_log.read_page(
        object_type=[audit_types.ObjectType.TAG], action=[audit_types.Action.CREATE, audit_types.Action.DELETE]
    )
    by_ref = audit_log.read_page(ref_type=audit_types.ObjectType.TAG, ref_id="1")

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
    assert [
        e.id
        for e in audit_log.read_page(
            ref_type=audit_types.ObjectType.ROLE, ref_name="ops", action=[audit_types.Action.UPDATE_NAME]
        ).entries
    ] == [entry.id]


def test_following_returns_the_same_entries_in_both_orders_and_across_pages(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [])
    role.update(role_id, name="operations")
    for i in range(4):
        role.update(role_id, description=f"v{i}")
    role.create("unrelated", "", [])
    role_type = audit_types.ObjectType.ROLE

    def read_all(descending: bool, limit: int) -> list[int]:
        ids: list[int] = []
        cursor = None
        while True:
            page = audit_log.read_page(
                ref_type=role_type, ref_name="ops", ref_follow=True, descending=descending, limit=limit, cursor=cursor
            )
            ids.extend(e.id for e in page.entries)
            cursor = page.next_cursor
            if page.is_last:
                return ids

    newest_first = read_all(descending=True, limit=2)
    oldest_first = read_all(descending=False, limit=2)

    assert len(newest_first) == 6
    assert oldest_first == sorted(newest_first)
    assert newest_first == sorted(newest_first, reverse=True)
    assert read_all(descending=True, limit=1000) == newest_first


@pytest.mark.parametrize(
    ("descending", "expected"),
    [(True, [5, 4, 3]), (False, [3, 4, 5])],
)
def test_the_objects_of_a_followed_name_are_fixed_for_the_whole_read(
    tenant_app_db: app_db.AppDb, descending: bool, expected: list[int]
) -> None:
    """The first page finds the objects. A rename to the same name between two pages changes nothing."""
    role_type = audit_types.ObjectType.ROLE
    other = role.create("x", "", [])  # entry 1
    role.update(other, description="old")  # entry 2
    ops = role.create("ops", "", [])  # entry 3
    role.update(ops, name="operations")  # entry 4
    role.update(ops, description="more")  # entry 5

    def read(limit: int, cursor: str | None) -> audit_log.Page:
        return audit_log.read_page(
            ref_type=role_type, ref_name="ops", ref_follow=True, descending=descending, limit=limit, cursor=cursor
        )

    page = read(limit=2, cursor=None)
    ids = [e.id for e in page.entries]
    assert not page.is_last
    role.update(other, name="ops")  # entry 6: `x` takes the followed name
    while not page.is_last:
        page = read(limit=2, cursor=page.next_cursor)
        ids.extend(e.id for e in page.entries)

    # `x` is not part of this read. A new read finds it.
    assert ids == expected
    fresh = audit_log.read_page(ref_type=role_type, ref_name="ops", ref_follow=True, descending=False)
    assert [e.id for e in fresh.entries] == [1, 2, 3, 4, 5, 6]


def test_a_name_that_matches_too_many_objects_cannot_be_followed(
    tenant_app_db: app_db.AppDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(audit_log, "MAX_FOLLOWED_OBJECTS", 2)
    for i in range(3):
        created = role.create("ops", "", [])
        role.update(created, name=f"gone{i}")

    with pytest.raises(audit_log.InvalidFilter, match="more than 2"):
        audit_log.read_page(ref_type=audit_types.ObjectType.ROLE, ref_name="ops", ref_follow=True)
    # Asking without following still works, and shows the ids to choose from.
    plain = audit_log.read_page(ref_type=audit_types.ObjectType.ROLE, ref_name="ops")
    assert len({r.object_id for refs in plain.refs.values() for r in refs}) == 3


def test_the_cursor_of_the_last_page_resumes_when_new_entries_arrive(tenant_app_db: app_db.AppDb) -> None:
    for i in range(3):
        audit_log.create(audit_types.TAG_CREATE, id=i, name=f"t{i}", value=None)

    caught_up = audit_log.read_page(descending=False, limit=100)
    assert caught_up.is_last
    nothing = audit_log.read_page(descending=False, limit=100, cursor=caught_up.next_cursor)
    audit_log.create(audit_types.TAG_CREATE, id=9, name="late", value=None)
    later = audit_log.read_page(descending=False, limit=100, cursor=caught_up.next_cursor)

    # An empty read does not move the position, so the entry that arrives later is not skipped.
    assert nothing.entries == []
    assert nothing.is_last
    assert nothing.next_cursor == caught_up.next_cursor
    assert [e.details["name"] for e in later.entries] == ["late"]
    assert later.is_last


def test_a_reader_can_start_on_an_empty_log(tenant_app_db: app_db.AppDb) -> None:
    empty = audit_log.read_page(descending=False)
    audit_log.create(audit_types.TAG_CREATE, id=1, name="first", value=None)

    after = audit_log.read_page(descending=False, cursor=empty.next_cursor)

    assert empty.entries == []
    assert empty.is_last
    assert [e.details["name"] for e in after.entries] == ["first"]


def test_a_cursor_of_another_version_is_refused(tenant_app_db: app_db.AppDb) -> None:

    page = audit_log.read_page()
    raw = json.loads(base64.urlsafe_b64decode(page.next_cursor + "=" * (-len(page.next_cursor) % 4)))
    raw["v"] = 2
    future = base64.urlsafe_b64encode(json.dumps(raw).encode()).decode().rstrip("=")

    with pytest.raises(audit_log.InvalidCursor, match="version"):
        audit_log.read_page(cursor=future)


def test_the_objects_behind_a_name_come_with_all_their_names(tenant_app_db: app_db.AppDb) -> None:
    first = role.create("ops", "", [])
    role.update(first, name="operations")
    second = role.create("ops", "", [])
    role.create("unrelated", "", [])

    page = audit_log.objects_with_name(audit_types.ObjectType.ROLE, "ops")

    assert page.is_last
    # Newest first: the object that got the name last comes first.
    assert [o.object_id for o in page.objects] == [str(second), str(first)]
    assert page.objects[1].names == ["ops", "operations"]
    assert page.objects[0].names == ["ops"]
    assert audit_log.objects_with_name(audit_types.ObjectType.ROLE, "nobody").objects == []


def _many_objects_named_ops(count: int, batch: str = "a") -> list[str]:
    """Each object takes the name, then gives it away, so that the next one can have it."""
    ids: list[str] = []
    for i in range(count):
        created = role.create("ops", "", [])
        role.update(created, name=f"gone-{batch}-{i}")
        ids.append(str(created))
    return ids


@pytest.mark.parametrize("descending", [True, False])
def test_objects_are_paged_whatever_their_number(tenant_app_db: app_db.AppDb, descending: bool) -> None:
    created = _many_objects_named_ops(7)
    role_type = audit_types.ObjectType.ROLE

    seen: list[str] = []
    pages = 0
    cursor = None
    while True:
        page = audit_log.objects_with_name(role_type, "ops", descending=descending, limit=3, cursor=cursor)
        assert len(page.objects) <= 3
        seen.extend(o.object_id for o in page.objects)
        pages += 1
        cursor = page.next_cursor
        if page.is_last:
            break

    assert pages == 3
    assert seen == (created[::-1] if descending else created)


def test_the_cursor_of_the_last_page_of_objects_resumes(tenant_app_db: app_db.AppDb) -> None:
    created = _many_objects_named_ops(2)
    role_type = audit_types.ObjectType.ROLE
    caught_up = audit_log.objects_with_name(role_type, "ops", descending=False, limit=100)
    nothing = audit_log.objects_with_name(role_type, "ops", descending=False, cursor=caught_up.next_cursor)
    late = _many_objects_named_ops(1, batch="b")
    later = audit_log.objects_with_name(role_type, "ops", descending=False, cursor=nothing.next_cursor)

    assert [o.object_id for o in caught_up.objects] == created
    assert nothing.objects == []
    assert nothing.is_last
    assert nothing.next_cursor == caught_up.next_cursor
    assert [o.object_id for o in later.objects] == late


def test_an_objects_cursor_cannot_change_query(tenant_app_db: app_db.AppDb) -> None:
    _many_objects_named_ops(3)
    role_type = audit_types.ObjectType.ROLE
    page = audit_log.objects_with_name(role_type, "ops", limit=1)

    with pytest.raises(audit_log.InvalidCursor):
        audit_log.objects_with_name(role_type, "ops", descending=False, cursor=page.next_cursor)
    with pytest.raises(audit_log.InvalidCursor):
        audit_log.objects_with_name(role_type, "other", cursor=page.next_cursor)
    # An entries cursor is not an objects cursor.
    with pytest.raises(audit_log.InvalidCursor):
        audit_log.objects_with_name(role_type, "ops", cursor=audit_log.read_page().next_cursor)
