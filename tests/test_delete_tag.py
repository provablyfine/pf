"""Deleting a tag: what changes because of it is recorded with the tag as its cause."""

import provablyfine_client as pfc

import tests.test_identity_self_token as base


def test_deleting_a_tag_records_the_identities_and_bastions_it_changed(api, tmp_path) -> None:
    factory, _admin, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    base._invite_second_identity(factory, sc, api.port, tmp_path)
    second = next(i for i in sc.list_identities().identities if i.name == "second")
    doomed = sc.create_tag("env", "doomed")
    kept = sc.create_tag("env", "kept")
    sc.update_identity(second.id, tags=[pfc.schemas.IdentityTagOp(type="add", tag_id_list=[doomed.id, kept.id])])
    bastion = sc.create_bastion("https://b", None, [doomed.id, kept.id], [])

    sc.delete_tag(doomed.id)

    entries = sc.list_audit_log(ref_type="tag", ref_id=str(doomed.id), order="asc").entries
    caused = {e.type: e for e in entries if "cause" in e.details}
    assert set(caused) == {"identity-remove-tags", "bastion-update"}
    assert all(
        e.details["cause"] == {"type": "tag", "id": str(doomed.id), "name": "env", "action": "delete"}
        for e in caused.values()
    )
    assert {r.id for r in caused["identity-remove-tags"].refs if r.type == "identity"} == {str(second.id)}
    assert {r.id for r in caused["bastion-update"].refs if r.type == "bastion"} == {str(bastion.id)}
    # The tag's own history ends with its deletion, after the changes it caused.
    assert entries[-1].type == "tag-delete"
    # The other tag is still on the identity.
    remaining = next(i for i in sc.list_identities().identities if i.id == second.id)
    assert [(t.name, t.value) for t in remaining.tags] == [("env", "kept")]
