"""A key that tries to use an invitation somebody else accepted is denied, and keeps being denied."""

import pathlib

import provablyfine_client as pfc
import pytest

import provablyfine.client
import provablyfine.jwk


def _key_file(directory: pathlib.Path, name: str) -> tuple[provablyfine.jwk.Private, str]:
    key = provablyfine.jwk.Private.generate_ed25519()
    path = directory / name
    path.write_bytes(key.to_pem())
    return key, str(path)


def test_second_key_on_an_accepted_invitation_is_denied_every_time(api, tmp_path) -> None:
    _, first_key_file = _key_file(tmp_path, "first.key")
    session_key, session_key_file = _key_file(tmp_path, "session.key")
    _, other_key_file = _key_file(tmp_path, "other.key")
    config = provablyfine.client.Config(
        directory_url=f"http://127.0.0.1:{api.port}/pf/t/00000000-0000-0000-0000-000000000001/directory",
        account_key_file=first_key_file,
        session_key_file=session_key_file,
    )
    factory = provablyfine.client.Factory(config)

    invitation = factory.public().initialize()
    factory.invitation(invitation, first_key_file).accept_invitation()

    with pytest.raises(pfc.exceptions.UI, match="Invitation was already accepted"):
        factory.invitation(invitation, other_key_file).accept_invitation()
    # Now the key is denied and is refused before anything else.
    with pytest.raises(pfc.exceptions.UI, match="Unable to use key"):
        factory.invitation(invitation, other_key_file).accept_invitation()

    result = factory.account(first_key_file, session_key_file).login_http_sig(session_key.public().to_dict())
    sc = factory.session()
    sc.update_session(result.roles[0].id)
    audit = [e.type for e in sc.list_audit_log().entries]
    assert audit.count("denylist-add") == 1
    # The refused retry is a rejected request: its warning must survive the rollback.
    assert audit.count("denylist-check-failed") == 1
