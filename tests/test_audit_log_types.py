import provablyfine_client as pfc
import pytest

import tests.test_identity_self_token as base


def test_the_server_lists_the_types_it_writes(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()

    actions = {t.object_type: t.actions for t in sc.list_audit_log_types().object_types}

    assert "remove-members" in actions["role"]
    assert "update-grant-list" in actions["role"]
    assert actions["certificate"] == ["create-user", "create-host"]
    # What the server no longer writes is not offered.
    assert "delete-cascade" not in [a for values in actions.values() for a in values]
    assert "unknown" not in actions


def test_a_wrong_action_says_what_the_valid_ones_are(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI, match="update-grant-list"):
        sc.list_audit_log(action="not-an-action")
