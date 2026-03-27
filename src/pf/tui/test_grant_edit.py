import pytest

from . import grant_edit

_Field = grant_edit._Field


# ---------------------------------------------------------------------------
# _Field.tag_filter
# ---------------------------------------------------------------------------


def test_field_tag_filter_inactive() -> None:
    assert _Field(active=False, value="a=1 b=2").tag_filter() is None


def test_field_tag_filter_active() -> None:
    assert _Field(active=True, value="env=prod region=us").tag_filter() == [
        {"name": "env", "value": "prod"},
        {"name": "region", "value": "us"},
    ]


def test_field_tag_filter_no_equals() -> None:
    assert _Field(active=True, value="noequals").tag_filter() == []


# ---------------------------------------------------------------------------
# _Field.tag_perm
# ---------------------------------------------------------------------------


def test_field_tag_perm_inactive() -> None:
    assert _Field(active=False, value="a=1").tag_perm() == []


def test_field_tag_perm_active() -> None:
    assert _Field(active=True, value="env=prod").tag_perm() == [{"name": "env", "value": "prod"}]


# ---------------------------------------------------------------------------
# _Field.boundary_filter
# ---------------------------------------------------------------------------


def test_field_boundary_filter_inactive() -> None:
    assert _Field(active=False, value="zone1").boundary_filter() is None


def test_field_boundary_filter_active() -> None:
    assert _Field(active=True, value="zone1 zone2").boundary_filter() == ["zone1", "zone2"]


# ---------------------------------------------------------------------------
# _Field.boundary_perm
# ---------------------------------------------------------------------------


def test_field_boundary_perm_inactive() -> None:
    assert _Field(active=False, value="zone1").boundary_perm() == []


def test_field_boundary_perm_active() -> None:
    assert _Field(active=True, value="zone1 zone2").boundary_perm() == ["zone1", "zone2"]


# ---------------------------------------------------------------------------
# _Field.invite_perm
# ---------------------------------------------------------------------------


def test_field_invite_perm_inactive() -> None:
    assert _Field(active=False, value="email").invite_perm() == []


def test_field_invite_perm_active_valid() -> None:
    assert _Field(active=True, value="email manual").invite_perm() == ["email", "manual"]


def test_field_invite_perm_filters_invalid_tokens() -> None:
    assert _Field(active=True, value="email fax manual sms").invite_perm() == ["email", "manual"]


# ---------------------------------------------------------------------------
# _Field.name_filter
# ---------------------------------------------------------------------------


def test_field_name_filter_inactive() -> None:
    assert _Field(active=False, value="root").name_filter() is None


def test_field_name_filter_active() -> None:
    assert _Field(active=True, value="root").name_filter() == "root"


def test_field_name_filter_blank() -> None:
    assert _Field(active=True, value="   ").name_filter() is None


# ---------------------------------------------------------------------------
# _Field.tag_name_value_filter
# ---------------------------------------------------------------------------


def test_field_tag_name_value_filter_inactive() -> None:
    assert _Field(active=False, value="env=prod").tag_name_value_filter() is None


def test_field_tag_name_value_filter_active() -> None:
    assert _Field(active=True, value="env=prod").tag_name_value_filter() == {
        "name": "env",
        "value": "prod",
    }


def test_field_tag_name_value_filter_no_equals() -> None:
    assert _Field(active=True, value="nopair").tag_name_value_filter() is None


def test_field_tag_name_value_filter_multiple_uses_first() -> None:
    assert _Field(active=True, value="a=1 b=2").tag_name_value_filter() == {
        "name": "a",
        "value": "1",
    }


# ---------------------------------------------------------------------------
# _Field.int_filter
# ---------------------------------------------------------------------------


def test_field_int_filter_inactive() -> None:
    assert _Field(active=False, value="42").int_filter() is None


def test_field_int_filter_active_digit() -> None:
    assert _Field(active=True, value="42").int_filter() == 42


def test_field_int_filter_non_digit() -> None:
    assert _Field(active=True, value="abc").int_filter() is None


# ---------------------------------------------------------------------------
# _Field.from_tag_list
# ---------------------------------------------------------------------------


def test_field_from_tag_list_none() -> None:
    f = _Field.from_tag_list(None)
    assert f.active is False
    assert f.value == ""


def test_field_from_tag_list_values() -> None:
    f = _Field.from_tag_list([{"name": "env", "value": "prod"}, {"name": "region", "value": "us"}])
    assert f.active is True
    assert f.value == "env=prod region=us"


# ---------------------------------------------------------------------------
# _Field.from_boundary_list
# ---------------------------------------------------------------------------


def test_field_from_boundary_list_none() -> None:
    f = _Field.from_boundary_list(None)
    assert f.active is False
    assert f.value == ""


def test_field_from_boundary_list_values() -> None:
    f = _Field.from_boundary_list(["zone1", "zone2"])
    assert f.active is True
    assert f.value == "zone1 zone2"


# ---------------------------------------------------------------------------
# _Field.from_invite_list
# ---------------------------------------------------------------------------


def test_field_from_invite_list_none() -> None:
    f = _Field.from_invite_list(None)
    assert f.active is False


def test_field_from_invite_list_values() -> None:
    f = _Field.from_invite_list(["email", "manual"])
    assert f.active is True
    assert f.value == "email manual"


# ---------------------------------------------------------------------------
# _resolve_update_perm
# ---------------------------------------------------------------------------


def test_resolve_update_perm_wildcard() -> None:
    assert grant_edit._resolve_update_perm(None, "name") is True
    assert grant_edit._resolve_update_perm(None, "description") is True


def test_resolve_update_perm_explicit() -> None:
    update = {"name": True, "description": False}
    assert grant_edit._resolve_update_perm(update, "name") is True
    assert grant_edit._resolve_update_perm(update, "description") is False


# ---------------------------------------------------------------------------
# new_grant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("grant_type", ["role", "identity", "tag", "boundary", "tenant", "ssh"])
def test_new_grant_structure(grant_type: str) -> None:
    g = grant_edit.new_grant(grant_type)
    assert g["type"] == grant_type
    assert "filter" in g
    assert "permission" in g
