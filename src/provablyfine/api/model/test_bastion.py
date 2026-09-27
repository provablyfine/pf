"""Deleting a tag drops it from every bastion's tag list, even a bastion's only tag."""

from .. import app_db
from ..context import ctx
from . import bastion, boundary, identity


def test_remove_tag_narrows_a_list_with_other_tags(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://b", None, [1, 42])

    changed = bastion.remove_tag(42)

    assert changed == [bastion_id]
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list == [1]


def test_remove_tag_strips_a_sole_tag_down_to_unrestricted(tenant_app_db: app_db.AppDb) -> None:
    # `tag_id_list is None` means every identity can see the bastion. Stripping the last tag
    # widens visibility rather than restricting it, which is fine: this field gates what a
    # bastion shows up as a jump host, not what an identity may do once connected.
    bastion_id = bastion.create("https://b", None, [42])

    changed = bastion.remove_tag(42)

    assert changed == [bastion_id]
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list is None


def test_remove_tag_ignores_a_bastion_that_does_not_reference_it(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://b", None, [1])

    changed = bastion.remove_tag(42)

    assert changed == []
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list == [1]


def test_remove_tag_leaves_an_unrestricted_bastion_alone(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://b", None, None)

    changed = bastion.remove_tag(42)

    assert changed == []
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list is None


def test_remove_tag_leaves_a_bastion_matching_no_one_alone(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://b", None, [])

    changed = bastion.remove_tag(42)

    assert changed == []
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list == []


def _identity(tag_id_list: list[int]) -> int:
    boundary_id = boundary.create("guard", "", None, [])
    return identity.create(name=f"id-{tag_id_list}", boundary_id_list=[boundary_id], tag_id_list=tag_id_list)


def test_read_matching_none_tag_id_list_matches_everyone(tenant_app_db: app_db.AppDb) -> None:
    unrestricted = bastion.create("https://b", None, None)
    caller_id = _identity([])

    with ctx.set_identity_id(caller_id):
        matching = bastion.read_matching()

    assert [b.id for b in matching] == [unrestricted]


def test_read_matching_empty_tag_id_list_matches_no_one(tenant_app_db: app_db.AppDb) -> None:
    other_tag_id = 999
    bastion.create("https://b", None, [])
    caller_id = _identity([other_tag_id])

    with ctx.set_identity_id(caller_id):
        matching = bastion.read_matching()

    assert matching == []


def test_read_matching_non_empty_tag_id_list_ors_against_caller_tags(tenant_app_db: app_db.AppDb) -> None:
    matches = bastion.create("https://b", None, [1, 2])
    bastion.create("https://c", None, [3])
    caller_id = _identity([2])

    with ctx.set_identity_id(caller_id):
        matching = bastion.read_matching()

    assert [b.id for b in matching] == [matches]
