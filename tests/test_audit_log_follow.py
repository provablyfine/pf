import provablyfine_client as pfc
import pytest

import tests.test_identity_self_token as base


def test_an_object_is_followed_through_a_rename_and_a_deletion(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    role = sc.create_role("ops", "")
    sc.update_role(role.id, name="operations")
    sc.delete_role(role.id)
    # Another role must not show up.
    sc.create_role("unrelated", "")

    plain = sc.list_audit_log(ref_type="role", ref_name="ops").entries
    followed = sc.list_audit_log(ref_type="role", ref_name="ops", ref_follow=True).entries

    assert sorted(e.type for e in plain) == ["role-create", "role-update-name"]
    assert sorted(e.type for e in followed) == ["role-create", "role-delete", "role-update-name"]
    assert {r.id for e in followed for r in e.refs} == {str(role.id)}


def test_following_pages_like_any_other_query(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    role = sc.create_role("ops", "")
    for i in range(4):
        sc.update_role(role.id, description=f"v{i}")

    entries = list(sc.iter_audit_log(ref_type="role", ref_name="ops", ref_follow=True, limit=2))

    assert len(entries) == 5
    assert [e.id for e in entries] == sorted((e.id for e in entries), reverse=True)


def test_a_cursor_cannot_be_used_with_other_filters(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    role = sc.create_role("ops", "")
    sc.update_role(role.id, description="v")
    page = sc.list_audit_log(ref_type="role", ref_name="ops", limit=1)
    assert not page.is_last

    with pytest.raises(pfc.exceptions.UI, match="Cursor does not match"):
        sc.list_audit_log(ref_type="role", ref_name="ops", ref_follow=True, limit=1, cursor=page.next_cursor)


def test_following_needs_a_name(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI, match="ref_follow needs ref_name"):
        sc.list_audit_log(ref_follow=True)


def test_a_reader_that_caught_up_resumes_with_the_cursor_it_saved(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()

    caught_up = sc.list_audit_log(order="asc", limit=1000)
    assert caught_up.is_last
    nothing = sc.list_audit_log(order="asc", limit=1000, cursor=caught_up.next_cursor)
    assert nothing.entries == []
    assert nothing.is_last
    sc.create_role("late", "")
    later = sc.list_audit_log(order="asc", limit=1000, cursor=nothing.next_cursor)

    assert [e.type for e in later.entries] == ["role-create"]
    assert later.is_last


def test_entry_ids_have_no_holes_even_when_requests_are_rejected(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    me = next(i.id for i in sc.list_identities().identities)
    sc.create_role("a", "")
    # The rejected request writes a warning in its own transaction and nothing else.
    with pytest.raises(pfc.exceptions.UI):
        sc.delete_identity(me)
    with pytest.raises(pfc.exceptions.UI):
        sc.create_role("a", "")
    sc.create_role("b", "")

    ids = [e.id for e in sc.iter_audit_log(order="asc", limit=3)]

    assert ids == list(range(1, len(ids) + 1))
    assert len(ids) > 3


def test_the_objects_behind_a_name_can_be_listed_and_asked_for_by_id(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    old = sc.create_role("ops", "")
    sc.update_role(old.id, name="operations")
    sc.delete_role(old.id)
    new = sc.create_role("ops", "")

    objects = sc.list_audit_log_objects("role", "ops").objects

    assert {o.id for o in objects} == {str(old.id), str(new.id)}
    assert next(o for o in objects if o.id == str(old.id)).names == ["ops", "operations"]
    # Each id gives the history of one object.
    history = sc.list_audit_log(ref_type="role", ref_id=str(old.id), order="asc").entries
    assert [e.type for e in history] == ["role-create", "role-update-name", "role-delete"]


def test_a_name_used_by_many_objects_can_be_listed_page_by_page(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    created = []
    for i in range(7):
        role = sc.create_role("ops", "")
        sc.update_role(role.id, name=f"gone{i}")
        created.append(str(role.id))

    first = sc.list_audit_log_objects("role", "ops", limit=3)
    everything = [o.id for o in sc.iter_audit_log_objects("role", "ops", limit=3)]

    assert len(first.objects) == 3
    assert not first.is_last
    assert everything == created[::-1]
    with pytest.raises(pfc.exceptions.UI, match="Cursor does not match"):
        sc.list_audit_log_objects("role", "ops", order="asc", limit=3, cursor=first.next_cursor)
