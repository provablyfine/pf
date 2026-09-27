"""Deleting a tag removes or rewrites the grants that name it, and only those."""

from .. import app_db
from . import boundary, grant, role, tag_references


def _ssh(tag_id_list: list[int] | None, host: str = "shell") -> grant.Grant:
    return grant.deserialize(
        {
            "type": "ssh",
            "filter": {"id": None, "tag_id_list": tag_id_list, "boundary_id_list": None},
            "permission": {
                "username_list": [host],
                "capability_list": ["shell"],
                "command_list": None,
                "max_session_ttl_s": None,
            },
        }
    )


def _tag_grant(tag_id: int | None) -> grant.Grant:
    return grant.deserialize(
        {
            "type": "tag",
            "filter": {"id": tag_id},
            "permission": {"create": False, "read": False, "delete": True},
        }
    )


def _identity_permission(
    add_tag_id_list: list[int] | None = None,
    del_tag_id_list: list[int] | None = None,
    create_tag_id_list: list[int] | None = None,
) -> dict[str, object]:
    return {
        "create": {
            "allowed": True,
            "allowed_tag_id_list": create_tag_id_list,
            "required_boundary_id_list": None,
        },
        "read": False,
        "update": None,
        "delete": False,
        "add_tag_id_list": add_tag_id_list,
        "del_tag_id_list": del_tag_id_list,
        "invite_list": None,
    }


def _identity(
    filter_tag_id_list: list[int] | None = None,
    add_tag_id_list: list[int] | None = None,
    del_tag_id_list: list[int] | None = None,
    create_tag_id_list: list[int] | None = None,
) -> grant.Grant:
    return grant.deserialize(
        {
            "type": "identity",
            "filter": {"id": None, "tag_id_list": filter_tag_id_list, "boundary_id_list": None},
            "permission": _identity_permission(add_tag_id_list, del_tag_id_list, create_tag_id_list),
        }
    )


def _audit(tenant_app_db: app_db.AppDb, type: str) -> list[app_db.AuditLogRow]:
    return [a for a in tenant_app_db.audit_log.read_all() if a.type == type]


def test_find_sees_a_filter_tag_id_list_on_an_ssh_grant(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_ssh([42])])
    assert [o.name for o in tag_references.find(42)] == ["ops"]


def test_find_sees_a_filter_tag_id_list_on_an_identity_grant(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_identity(filter_tag_id_list=[42])])
    assert [o.name for o in tag_references.find(42)] == ["ops"]


def test_find_sees_an_add_tag_id_list(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_identity(add_tag_id_list=[42])])
    assert [o.name for o in tag_references.find(42)] == ["ops"]


def test_find_sees_a_del_tag_id_list(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_identity(del_tag_id_list=[42])])
    assert [o.name for o in tag_references.find(42)] == ["ops"]


def test_find_sees_a_create_allowed_tag_id_list(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_identity(create_tag_id_list=[42])])
    assert [o.name for o in tag_references.find(42)] == ["ops"]


def test_find_sees_boundary_ceiling_and_denied_lists(tenant_app_db: app_db.AppDb) -> None:
    boundary.create("ceiling-guard", "", [_ssh([42])], [])
    boundary.create("denied-guard", "", None, [_ssh([42])])
    assert {o.name for o in tag_references.find(42)} == {"ceiling-guard", "denied-guard"}


def test_find_is_empty_when_nothing_names_the_tag(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_ssh([1]), _identity(add_tag_id_list=[2])])
    assert tag_references.find(42) == []


def test_find_does_not_see_a_tag_grant_about_the_tag_object(tenant_app_db: app_db.AppDb) -> None:
    # A `TagGrant` on `filter.id` is a permission to manage the tag object itself
    # (e.g. "may delete tag 42"), not a filter that matches identities by tag.
    # It must never feed the refusal decision.
    role.create("ops", "", [_tag_grant(42)])
    assert tag_references.find(42) == []


def test_remove_drops_a_filter_grant_whole_even_with_other_tags_in_the_list(tenant_app_db: app_db.AppDb) -> None:
    # Shrinking the list in place would widen the grant to match on tag 1 alone,
    # which nobody satisfies today because tag 42 is required too.
    role_id = role.create("ops", "", [_ssh([1, 42]), _ssh([1])])

    changed = tag_references.remove(42)

    assert [o.name for o in changed] == ["ops"]
    kept = role.read_one(role_id)
    assert kept is not None
    assert [g.filter.tag_id_list for g in kept.grant_list if isinstance(g, grant.SSHGrant)] == [[1]]


def test_remove_strips_the_tag_from_an_add_tag_id_list_and_keeps_the_grant(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [_identity(add_tag_id_list=[1, 42])])

    tag_references.remove(42)

    kept = role.read_one(role_id)
    assert kept is not None
    [g] = kept.grant_list
    assert isinstance(g, grant.IdentityGrant)
    assert g.permission.add_tag_id_list == [1]
    assert g.permission.del_tag_id_list is None


def test_remove_strips_the_tag_from_a_del_tag_id_list_and_keeps_the_grant(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [_identity(del_tag_id_list=[1, 42])])

    tag_references.remove(42)

    kept = role.read_one(role_id)
    assert kept is not None
    [g] = kept.grant_list
    assert isinstance(g, grant.IdentityGrant)
    assert g.permission.del_tag_id_list == [1]


def test_remove_strips_the_tag_from_a_create_allowed_tag_id_list_and_keeps_the_grant(
    tenant_app_db: app_db.AppDb,
) -> None:
    role_id = role.create("ops", "", [_identity(create_tag_id_list=[1, 42])])

    tag_references.remove(42)

    kept = role.read_one(role_id)
    assert kept is not None
    [g] = kept.grant_list
    assert isinstance(g, grant.IdentityGrant)
    assert g.permission.create is not None
    assert g.permission.create.allowed_tag_id_list == [1]


def test_remove_drops_a_tag_grant_about_the_tag_object(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [_tag_grant(42), _tag_grant(None)])

    changed = tag_references.remove(42)

    assert [o.name for o in changed] == ["ops"]
    kept = role.read_one(role_id)
    assert kept is not None
    assert [g.filter.id for g in kept.grant_list if isinstance(g, grant.TagGrant)] == [None]


def test_remove_leaves_a_tag_grant_with_no_filter_id_alone(tenant_app_db: app_db.AppDb) -> None:
    role_id = role.create("ops", "", [_tag_grant(None)])

    assert tag_references.remove(42) == []
    kept = role.read_one(role_id)
    assert kept is not None
    assert len(kept.grant_list) == 1


def test_changed_grants_are_written_to_the_audit_log(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_ssh([42])])
    boundary.create("guard", "", None, [_ssh([42])])

    tag_references.remove(42)

    entries = {
        (a.details["owner_name"], a.details["list"]): a.details for a in _audit(tenant_app_db, "tag-delete-cascade")
    }
    assert set(entries) == {("ops", "grant_list"), ("guard", "denied_list")}
    for details in entries.values():
        assert details["tag_id"] == 42
        assert [g["filter"]["tag_id_list"] for g in details["affected_grants"]] == [[42]]


def test_a_ceiling_that_loses_its_last_grant_denies_everything(tenant_app_db: app_db.AppDb) -> None:
    boundary_id = boundary.create("guard", "", [_ssh([42])], [])

    tag_references.remove(42)

    remaining = boundary.read_one(id=boundary_id)
    assert remaining is not None
    # `[]` denies everything. `None` would mean "no ceiling" and would widen the boundary.
    assert remaining.ceiling_list == []


def test_a_boundary_without_a_ceiling_keeps_having_none(tenant_app_db: app_db.AppDb) -> None:
    boundary_id = boundary.create("guard", "", None, [_ssh([42])])

    tag_references.remove(42)

    remaining = boundary.read_one(id=boundary_id)
    assert remaining is not None
    assert remaining.ceiling_list is None
    assert remaining.denied_list == []


def test_nothing_changes_when_no_grant_names_the_tag(tenant_app_db: app_db.AppDb) -> None:
    role.create("ops", "", [_ssh([1])])
    boundary.create("guard", "", [_ssh([1])], [_ssh([1])])
    before = _audit(tenant_app_db, "role-update-grant-list")

    assert tag_references.remove(42) == []
    assert tag_references.find(42) == []
    assert _audit(tenant_app_db, "tag-delete-cascade") == []
    assert _audit(tenant_app_db, "role-update-grant-list") == before
