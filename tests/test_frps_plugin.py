"""Integration tests for the frps auth plugin endpoint."""

import base64
import json

import requests

import provablyfine.client
import provablyfine.jwk


def _jwt_audience(token: str) -> str:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return str(json.loads(base64.urlsafe_b64decode(payload))["aud"])


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


def test_frps_plugin_accept(api, tmp_path):
    factory, identity_name = _setup_session(api.port, tmp_path)
    token_response = factory.session().get_self_token("bastion", hostname=identity_name)
    frpc_user = _jwt_audience(token_response.token)

    response = requests.post(
        f"http://127.0.0.1:{api.port}/frps/plugin",
        json={
            "op": "Login",
            "content": {
                "user": frpc_user,
                "privilege_key": token_response.token,
            },
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["reject"] is False


def test_frps_plugin_wrong_user(api, tmp_path):
    factory, identity_name = _setup_session(api.port, tmp_path)
    token_response = factory.session().get_self_token("bastion", hostname=identity_name)

    response = requests.post(
        f"http://127.0.0.1:{api.port}/frps/plugin",
        json={
            "op": "Login",
            "content": {
                "user": "wrong-hostname",
                "privilege_key": token_response.token,
            },
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["reject"] is True


def test_frps_plugin_missing_jwt(api, tmp_path):
    _setup_session(api.port, tmp_path)

    response = requests.post(
        f"http://127.0.0.1:{api.port}/frps/plugin",
        json={
            "op": "Login",
            "content": {
                "user": "alice",
                "metas": {},
            },
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["reject"] is True


def test_frps_plugin_non_login_op(api, tmp_path):
    response = requests.post(
        f"http://127.0.0.1:{api.port}/frps/plugin",
        json={
            "op": "NewProxy",
            "content": {
                "user": {"user": "alice", "metas": {}, "run_id": "abc"},
                "proxy_name": "ssh",
                "proxy_type": "tcpMuxHTTPConnect",
            },
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["reject"] is False
