"""Deleting a bastion: the grants that name it go with it, and the audit log keeps the story."""

import provablyfine_client as pfc

import tests.test_identity_self_token as base


def _bastion_grant(bastion_id: int | None) -> pfc.schemas.Grant:
    return pfc.schemas.validate_grant(
        {
            "type": "bastion",
            "filter": {"id": bastion_id},
            "permission": {"create": False, "read": True, "delete": False, "update": None},
        }
    )


def test_deleting_a_bastion_removes_the_grants_that_name_it(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    doomed = sc.create_bastion("https://doomed", None, None, [])
    kept = sc.create_bastion("https://kept", None, None, [])

    role = sc.create_role("ops", "")
    sc.update_role(role.id, grant_list=[_bastion_grant(doomed.id), _bastion_grant(kept.id)])
    guard = sc.create_boundary("guard", "")
    sc.update_boundary(guard.id, ceiling_list=[_bastion_grant(doomed.id)], denied_list=[_bastion_grant(doomed.id)])

    sc.delete_bastion(doomed.id)

    roles = {r.name: r for r in sc.list_roles().roles}
    boundaries = {b.name: b for b in sc.list_boundaries().boundaries}
    assert [g.filter.id for g in roles["ops"].grant_list] == [kept.id]
    assert boundaries["guard"].denied_list == []
    # An emptied ceiling denies everything. It must not become "no ceiling".
    assert boundaries["guard"].ceiling_list == []

    entries = [e for e in sc.list_audit_log().entries if e.type == "bastion-delete-cascade"]
    assert {(e.details["owner_name"], e.details["list"]) for e in entries} == {
        ("ops", "grant_list"),
        ("guard", "denied_list"),
        ("guard", "ceiling_list"),
    }
    assert all(e.details["bastion_id"] == doomed.id for e in entries)
