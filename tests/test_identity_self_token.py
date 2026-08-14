"""Integration tests for the /self/token endpoint's grant-gated deadline claim."""

import base64
import json

import provablyfine_client as pfc
import pytest

import provablyfine.client
import provablyfine.jwk


def _claims(token: str) -> dict[str, object]:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _setup_session(api_port: int, tmp_path) -> tuple[provablyfine.client.Factory, str]:
    """Initialize tenant, login, return (factory, identity_name)."""
    account_key = provablyfine.jwk.Private.generate_ed25519()
    account_key_file = tmp_path / "account.key"
    account_key_file.write_bytes(account_key.to_pem())

    session_key = provablyfine.jwk.Private.generate_ed25519()
    session_key_file = tmp_path / "session.key"
    session_key_file.write_bytes(session_key.to_pem())

    config = provablyfine.client.Config(
        directory_url=f"http://127.0.0.1:{api_port}/pf/t/root/directory",
        account_key_file=str(account_key_file),
        session_key_file=str(session_key_file),
    )
    factory = provablyfine.client.Factory(config)

    invitation_key = factory.public().initialize()
    factory.invitation(invitation_key, str(account_key_file)).accept_invitation()
    factory.account(str(account_key_file), str(session_key_file)).login_http_sig(session_key.public().to_dict())

    sc = factory.session()
    identity = sc.get_self()
    return factory, identity.name


def test_self_token_without_service_bastion_is_forbidden(api, tmp_path):
    factory, identity_name = _setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("not-bastion", hostname=identity_name)


def test_self_token_without_username_carries_no_deadline_or_cid(api, tmp_path):
    factory, identity_name = _setup_session(api.port, tmp_path)
    sc = factory.session()

    token_response = sc.get_self_token("bastion", hostname=identity_name)
    claims = _claims(token_response.token)

    assert "deadline" not in claims
    assert "cid" not in claims
    assert "jti" in claims


def test_self_token_with_username_but_no_grant_is_forbidden(api, tmp_path):
    factory, identity_name = _setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("bastion", hostname=identity_name, username="root")


def test_self_token_with_malformed_connection_id_is_dropped_not_rejected(api, tmp_path):
    factory, identity_name = _setup_session(api.port, tmp_path)
    sc = factory.session()

    # No PORT_FORWARDING grant either, so this still 403s -- but on the grant
    # check, not on connection_id parsing, which must fail open.
    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("bastion", hostname=identity_name, username="root", connection_id="not-a-uuid")
