"""Integration tests for the /self/token endpoint's purpose split and mirrored deadline."""

import base64
import json
import time

import provablyfine_client as pfc
import pytest

import provablyfine.client
import provablyfine.jwk


def _claims(token: str) -> dict[str, object]:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def _setup_session(api_port: int, tmp_path) -> tuple[provablyfine.client.Factory, str, int]:
    """Initialize tenant, login, return (factory, identity_name, active_role_id)."""
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
    result = factory.account(str(account_key_file), str(session_key_file)).login_http_sig(
        session_key.public().to_dict()
    )

    sc = factory.session()
    # Grants only apply once a role is activated on the session.
    role_id = result.roles[0].id
    sc.update_session(role_id)
    identity = sc.get_self()
    return factory, identity.name, role_id


def _grant_shell(sc: pfc.SessionClient, role_id: int, hostname: str, max_session_ttl_s: int | None) -> None:
    """Append a shell grant for `hostname` to the session's already-active role."""
    role = sc.get_role(role_id)
    grant = pfc.schemas.validate_grant(
        {
            "type": "ssh",
            "filter": {"name": hostname},
            "permission": {
                "username_list": ["root"],
                "capability_list": ["shell"],
                "command_list": None,
                "max_session_ttl_s": max_session_ttl_s,
            },
        }
    )
    sc.update_role(role_id, grant_list=[*role.grant_list, grant])


def _sign_cert(sc: pfc.SessionClient, hostname: str) -> str:
    """Request a shell certificate and return its connection_id."""
    key = provablyfine.jwk.Private.generate_ed25519()
    response = sc.get_user_certificate(
        hostname=hostname, username="root", action="shell", public_key=key.public().to_dict()
    )
    return response.connection_id


def test_self_token_without_service_bastion_is_forbidden(api, tmp_path):
    factory, identity_name, _role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("not-bastion", hostname=identity_name, purpose="register")


def test_register_token_carries_no_deadline_or_cid(api, tmp_path):
    factory, identity_name, _role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()

    token_response = sc.get_self_token("bastion", hostname=identity_name, purpose="register")
    claims = _claims(token_response.token)

    assert claims["use"] == "register"
    assert "deadline" not in claims
    assert "cid" not in claims
    assert "jti" in claims


def test_register_token_for_another_host_is_forbidden(api, tmp_path):
    factory, _, _role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("bastion", hostname="some-other-host", purpose="register")


def test_connect_token_without_connection_id_is_rejected(api, tmp_path):
    factory, identity_name, _role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("bastion", hostname=identity_name, purpose="connect")


def test_connect_token_with_unknown_connection_id_is_forbidden(api, tmp_path):
    factory, identity_name, _role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token(
            "bastion", hostname=identity_name, purpose="connect", connection_id="11111111-2222-3333-4444-555555555555"
        )


def test_connect_token_mirrors_the_certificate_deadline(api, tmp_path):
    factory, identity_name, role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()
    _grant_shell(sc, role_id, identity_name, max_session_ttl_s=3600)

    signed_at = int(time.time())
    connection_id = _sign_cert(sc, identity_name)

    claims = _claims(
        sc.get_self_token("bastion", hostname=identity_name, purpose="connect", connection_id=connection_id).token
    )
    assert claims["use"] == "connect"
    assert claims["cid"] == connection_id
    deadline = claims["deadline"]
    assert isinstance(deadline, int)
    assert signed_at + 3600 <= deadline <= signed_at + 3601

    # The deadline is anchored to certificate-signing time, not to token
    # issuance: a later reconnect must not extend the session. This is what
    # keeps the relay and the target host's PAM hook in agreement.
    time.sleep(1)
    again = _claims(
        sc.get_self_token("bastion", hostname=identity_name, purpose="connect", connection_id=connection_id).token
    )
    assert again["deadline"] == deadline


def test_connect_token_for_unbounded_grant_has_cid_but_no_deadline(api, tmp_path):
    factory, identity_name, role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()
    _grant_shell(sc, role_id, identity_name, max_session_ttl_s=None)

    connection_id = _sign_cert(sc, identity_name)
    claims = _claims(
        sc.get_self_token("bastion", hostname=identity_name, purpose="connect", connection_id=connection_id).token
    )

    assert claims["cid"] == connection_id
    assert "deadline" not in claims


def test_connect_token_for_another_hostname_is_forbidden(api, tmp_path):
    factory, identity_name, role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()
    _grant_shell(sc, role_id, identity_name, max_session_ttl_s=3600)

    connection_id = _sign_cert(sc, identity_name)

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("bastion", hostname="some-other-host", purpose="connect", connection_id=connection_id)


def test_connect_token_for_another_identitys_connection_is_forbidden(api, tmp_path):
    factory, identity_name, role_id = _setup_session(api.port, tmp_path)
    sc = factory.session()
    _grant_shell(sc, role_id, identity_name, max_session_ttl_s=3600)
    connection_id = _sign_cert(sc, identity_name)

    other = _invite_second_identity(factory, sc, api.port, tmp_path)
    with pytest.raises(pfc.exceptions.UI):
        other.get_self_token("bastion", hostname=identity_name, purpose="connect", connection_id=connection_id)


def _invite_second_identity(
    factory: provablyfine.client.Factory, sc: pfc.SessionClient, api_port: int, tmp_path
) -> pfc.SessionClient:
    identity = sc.create_identity(
        name="second", boundary_id_list=[], boundary_name_list=[], tag_id_list=[], tag_name_value_list=[]
    )
    invitation_key = sc.invite_identity(identity.id, "manual")
    assert invitation_key is not None
    account_key = provablyfine.jwk.Private.generate_ed25519()
    account_key_file = tmp_path / "second-account.key"
    account_key_file.write_bytes(account_key.to_pem())
    session_key = provablyfine.jwk.Private.generate_ed25519()
    session_key_file = tmp_path / "second-session.key"
    session_key_file.write_bytes(session_key.to_pem())

    config = provablyfine.client.Config(
        directory_url=f"http://127.0.0.1:{api_port}/pf/t/root/directory",
        account_key_file=str(account_key_file),
        session_key_file=str(session_key_file),
    )
    other_factory = provablyfine.client.Factory(config)
    other_factory.invitation(invitation_key, str(account_key_file)).accept_invitation()
    other_factory.account(str(account_key_file), str(session_key_file)).login_http_sig(session_key.public().to_dict())
    return other_factory.session()
