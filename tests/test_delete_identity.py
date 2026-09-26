"""Deleting an identity: the grants that name it go with it, and the audit log keeps the story."""

import provablyfine_client as pfc
import pytest

import tests.test_identity_self_token as base


def _ssh_grant(hostname: str) -> pfc.schemas.Grant:
    return pfc.schemas.validate_grant(
        {
            "type": "ssh",
            "filter": {"name": hostname},
            "permission": {
                "username_list": ["root"],
                "capability_list": ["shell"],
                "command_list": None,
                "max_session_ttl_s": None,
            },
        }
    )


def _identity_id(sc: pfc.SessionClient, name: str) -> int:
    return next(i.id for i in sc.list_identities().identities if i.name == name)


def _audit(sc: pfc.SessionClient, type: str) -> list[pfc.schemas.AuditLogEntry]:
    return [e for e in sc.list_audit_log().entries if e.type == type]


def test_deleting_an_identity_removes_the_grants_that_name_it(api, tmp_path) -> None:
    factory, admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    base._invite_second_identity(factory, sc, api.port, tmp_path)
    second_id = _identity_id(sc, "second")

    role = sc.create_role("ops", "")
    sc.update_role(role.id, grant_list=[_ssh_grant("second"), _ssh_grant(admin)])
    guard = sc.create_boundary("guard", "")
    sc.update_boundary(
        guard.id, ceiling_list=[_ssh_grant("second")], denied_list=[_ssh_grant("second"), _ssh_grant(admin)]
    )

    sc.delete_identity(second_id)

    # Every listing works, and no "invalid" grant is left behind. A grant naming a deleted identity used to
    # stay, rendered as an invalid grant that cannot be sent back to the server.
    roles = {r.name: r for r in sc.list_roles().roles}
    boundaries = {b.name: b for b in sc.list_boundaries().boundaries}
    sc.list_bastions()
    sc.list_identities()
    assert [g.filter.name for g in roles["ops"].grant_list] == [admin]
    assert [g.filter.name for g in boundaries["guard"].denied_list] == [admin]
    # An emptied ceiling denies everything. It must not become "no ceiling".
    assert boundaries["guard"].ceiling_list == []


def test_the_cascade_entries_carry_the_removed_grants(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    base._invite_second_identity(factory, sc, api.port, tmp_path)
    second_id = _identity_id(sc, "second")
    guard = sc.create_boundary("guard", "")
    sc.update_boundary(guard.id, denied_list=[_ssh_grant("second")])

    sc.delete_identity(second_id)

    (entry,) = _audit(sc, "identity-delete-cascade")
    assert entry.details["identity_id"] == second_id
    assert entry.details["owner_name"] == "guard"
    assert entry.details["list"] == "denied_list"
    assert len(entry.details["removed_grants"]) == 1
    assert entry.details["removed_grants"][0]["filter"]["id"] == second_id


def test_the_sessions_of_a_deleted_identity_stop_and_are_recorded(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    other = base._invite_second_identity(factory, sc, api.port, tmp_path)
    second_id = _identity_id(sc, "second")
    other.get_self()

    sc.delete_identity(second_id)

    with pytest.raises(pfc.exceptions.UI):
        other.get_self()
    (entry,) = _audit(sc, "identity-delete")
    assert entry.details["id"] == second_id
    assert entry.details["name"] == "second"
    assert entry.details["session_count"] == 1
    (session,) = entry.details["live_sessions"]
    assert session["login_ip"] == "127.0.0.1"


def test_every_login_is_audited(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    base._invite_second_identity(factory, sc, api.port, tmp_path)
    second_id = _identity_id(sc, "second")

    logins = _audit(sc, "session-create")

    assert [e.details["method"] for e in logins] == ["http_sig", "http_sig"]
    assert {e.details["identity_id"] for e in logins} == {1, second_id}
    assert {e.details["login_ip"] for e in logins} == {"127.0.0.1"}
    assert all(e.details["session_key_id"] for e in logins)


def test_refused_deletions_are_audited(api, tmp_path) -> None:
    factory, admin, role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    other = base._invite_second_identity(factory, sc, api.port, tmp_path)
    second_id = _identity_id(sc, "second")
    # Make the second identity an administrator too, so that it is allowed to try.
    sc.update_role(
        role_id,
        member_list=[
            pfc.schemas.RoleMemberUpdateRequest(name=admin),
            pfc.schemas.RoleMemberUpdateRequest(name="second"),
        ],
    )
    other.update_session(role_id)

    with pytest.raises(pfc.exceptions.UI, match="cannot delete yourself"):
        other.delete_identity(second_id)
    with pytest.raises(pfc.exceptions.UI, match="founding identity"):
        other.delete_identity(1)

    refusals = {e.details["reason"]: e for e in _audit(sc, "identity-delete-refused")}
    assert set(refusals) == {"self", "founding"}
    assert refusals["founding"].details["identity_id"] == 1
    assert refusals["founding"].by_identity_id == str(second_id)
    assert refusals["self"].details["identity_id"] == second_id
    # The refusals changed nothing.
    assert _identity_id(sc, admin) == 1
    assert _identity_id(sc, "second") == second_id
