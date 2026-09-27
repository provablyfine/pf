"""Deleting a tag drops it from every bastion's tag list, even a bastion's only tag."""

from .. import app_db
from . import bastion


def test_remove_tag_narrows_a_list_with_other_tags(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://b", None, [1, 42])

    changed = bastion.remove_tag(42)

    assert changed == [bastion_id]
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list == [1]


def test_remove_tag_strips_a_sole_tag_down_to_unrestricted(tenant_app_db: app_db.AppDb) -> None:
    # `tag_id_list == []` means every identity can see the bastion. Stripping the last tag
    # widens visibility rather than restricting it, which is fine: this field gates what a
    # bastion shows up as a jump host, not what an identity may do once connected.
    bastion_id = bastion.create("https://b", None, [42])

    changed = bastion.remove_tag(42)

    assert changed == [bastion_id]
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list == []


def test_remove_tag_ignores_a_bastion_that_does_not_reference_it(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://b", None, [1])

    changed = bastion.remove_tag(42)

    assert changed == []
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list == [1]


def test_remove_tag_leaves_an_unrestricted_bastion_alone(tenant_app_db: app_db.AppDb) -> None:
    bastion_id = bastion.create("https://b", None, [])

    changed = bastion.remove_tag(42)

    assert changed == []
    kept = bastion.read_one(id=bastion_id)
    assert kept is not None
    assert kept.tag_id_list == []
