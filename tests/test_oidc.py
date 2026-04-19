"""OIDC login e2e tests."""

import dataclasses
import json
import os
import threading
import time
import typing

import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import pytest
import requests

import pf.cli.login as login
import pf.client
import pf.client.exceptions
import pf.client.sync
import pf.jwk as jwk
import pf.ssh.agent as ssh_agent_module

from . import mock_oidc


def _create_session_key() -> tuple[jwk.Private, str]:
    """Create a session key, add to SSH agent, return (key, fingerprint)."""
    session_key = jwk.Private.generate_ed25519()
    ssh_agent = ssh_agent_module.Client()
    ssh_agent.add(session_key, comment="test-session", lifetime=300)
    session_fingerprint = session_key.public().ssh_fingerprint()
    return session_key, session_fingerprint


@dataclasses.dataclass
class OidcEnv:
    """Test environment with OIDC setup."""

    config: pf.client.Config
    sc: pf.client.sync.Client
    mock: mock_oidc.MockOidcProvider


@pytest.fixture
def oidc_env(api, mock_oidc, ssh_agent, tmp_path) -> typing.Iterator[OidcEnv]:
    """Set up OIDC test environment: tenant initialized, auth config, identity, SSH agent."""
    # Set SSH_AUTH_SOCK early so SSH agent is available for key operations
    old_ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")
    os.environ["SSH_AUTH_SOCK"] = ssh_agent.socket

    try:
        # Write temporary account key file
        account_key_obj = jwk.Private.generate_ed25519()
        account_key_file = tmp_path / "account_key"
        account_key_file.write_bytes(account_key_obj.to_pem())

        # Initialize Config pointing to the API (no session key yet)
        config = pf.client.Config(
            directory_url=f"http://127.0.0.1:{api.port}/pf/t/root/directory",
            account_key=str(account_key_file),
        )

        # Create sync client and initialize tenant
        sc = pf.client.sync.Client(config)
        sc.initialize(str(account_key_file))

        # Generate session key and login via http_sig
        session_key_obj = jwk.Private.generate_ed25519()
        session_key_file = tmp_path / "session_key"
        session_key_file.write_bytes(session_key_obj.to_pem())
        session_fingerprint = str(session_key_file)  # Full path for http_sig_login

        sc.http_sig_login(
            session_public_key=session_key_obj.public().to_dict(),
            session_fingerprint=session_fingerprint,
        )

        # Update config to include session key so subsequent calls work
        config = pf.client.Config(
            directory_url=config.directory_url,
            account_key=config.account_key,
            session_key=str(session_key_file),
        )
        sc = pf.client.sync.Client(config)

        # Create OIDC auth config pointing to mock OIDC provider
        sc.create_auth_oidc(
            name="oidc-test",
            description="Test OIDC provider",
            tags=[],
            issuer=mock_oidc.issuer,
            client_id=mock_oidc.client_id,
            client_secret=None,
        )

        # Create identity with email matching the mock token
        sc.create_identity(
            name="user@example.com",
            boundary_id_list=[],
            boundary_name_list=[],
            tag_id_list=[],
            tag_name_value_list=[],
        )

        yield OidcEnv(config=config, sc=sc, mock=mock_oidc)
    finally:
        # Cleanup SSH_AUTH_SOCK
        if old_ssh_auth_sock is None:
            os.environ.pop("SSH_AUTH_SOCK", None)
        else:
            os.environ["SSH_AUTH_SOCK"] = old_ssh_auth_sock


# =============================================================================
# Group A: Server endpoint tests (call sc.oidc_login directly)
# =============================================================================


def test_endpoint_rs256(oidc_env: OidcEnv) -> None:
    """Valid RS256 token succeeds."""
    id_token = oidc_env.mock.issue_token("user@example.com", alg="RS256")
    session_key, session_fingerprint = _create_session_key()

    oidc_env.sc.oidc_login(
        auth_name="oidc-test",
        id_token=id_token,
        session_public_key=session_key.public().to_dict(),
        session_fingerprint=session_fingerprint,
    )


def test_endpoint_es256(oidc_env: OidcEnv) -> None:
    """Valid ES256 token succeeds."""
    id_token = oidc_env.mock.issue_token("user@example.com", alg="ES256")
    session_key, session_fingerprint = _create_session_key()

    oidc_env.sc.oidc_login(
        auth_name="oidc-test",
        id_token=id_token,
        session_public_key=session_key.public().to_dict(),
        session_fingerprint=session_fingerprint,
    )


def test_endpoint_expired(oidc_env: OidcEnv) -> None:
    """Expired token is rejected."""
    id_token = oidc_env.mock.issue_token("user@example.com", expired=True)
    session_key, session_fingerprint = _create_session_key()

    with pytest.raises(pf.client.exceptions.UI):
        oidc_env.sc.oidc_login(
            auth_name="oidc-test",
            id_token=id_token,
            session_public_key=session_key.public().to_dict(),
            session_fingerprint=session_fingerprint,
        )


def test_endpoint_wrong_issuer(oidc_env: OidcEnv) -> None:
    """Token with wrong issuer is rejected."""
    id_token = oidc_env.mock.issue_token(
        "user@example.com", issuer="https://evil.example.com"
    )
    session_key, session_fingerprint = _create_session_key()

    with pytest.raises(pf.client.exceptions.UI):
        oidc_env.sc.oidc_login(
            auth_name="oidc-test",
            id_token=id_token,
            session_public_key=session_key.public().to_dict(),
            session_fingerprint=session_fingerprint,
        )


def test_endpoint_wrong_audience(oidc_env: OidcEnv) -> None:
    """Token with wrong audience is rejected."""
    id_token = oidc_env.mock.issue_token(
        "user@example.com", audience="wrong-client"
    )
    session_key, session_fingerprint = _create_session_key()

    with pytest.raises(pf.client.exceptions.UI):
        oidc_env.sc.oidc_login(
            auth_name="oidc-test",
            id_token=id_token,
            session_public_key=session_key.public().to_dict(),
            session_fingerprint=session_fingerprint,
        )


def test_endpoint_missing_email(oidc_env: OidcEnv) -> None:
    """Token without email claim is rejected."""
    # Manually build a token without email claim
    header = {"alg": "RS256", "typ": "JWT", "kid": "rsa-1"}
    payload = {
        "iss": oidc_env.mock.issuer,
        "aud": oidc_env.mock.client_id,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    # Notably missing "email"
    header_b64 = mock_oidc._b64url_encode(json.dumps(header).encode())
    payload_b64 = mock_oidc._b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = oidc_env.mock._rsa_key.sign(
        signing_input,
        cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
        cryptography.hazmat.primitives.hashes.SHA256(),
    )
    signature_b64 = mock_oidc._b64url_encode(signature)
    id_token = f"{header_b64}.{payload_b64}.{signature_b64}"

    session_key, session_fingerprint = _create_session_key()

    with pytest.raises(pf.client.exceptions.UI):
        oidc_env.sc.oidc_login(
            auth_name="oidc-test",
            id_token=id_token,
            session_public_key=session_key.public().to_dict(),
            session_fingerprint=session_fingerprint,
        )


def test_endpoint_unknown_auth(oidc_env: OidcEnv) -> None:
    """Login with unknown auth config fails."""
    id_token = oidc_env.mock.issue_token("user@example.com")
    session_key, session_fingerprint = _create_session_key()

    with pytest.raises(pf.client.exceptions.UI):
        oidc_env.sc.oidc_login(
            auth_name="no-such-auth",
            id_token=id_token,
            session_public_key=session_key.public().to_dict(),
            session_fingerprint=session_fingerprint,
        )


def test_endpoint_tag_restriction_pass(oidc_env: OidcEnv) -> None:
    """Login succeeds when auth has no tag restrictions."""
    # Create a basic auth config with no tag restrictions
    oidc_env.sc.create_auth_oidc(
        name="oidc-unrestricted",
        description="Unrestricted OIDC",
        tags=[],
        issuer=oidc_env.mock.issuer,
        client_id=oidc_env.mock.client_id,
        client_secret=None,
    )

    # Login should succeed since there are no tag restrictions
    id_token = oidc_env.mock.issue_token("user@example.com")
    session_key, session_fingerprint = _create_session_key()

    oidc_env.sc.oidc_login(
        auth_name="oidc-unrestricted",
        id_token=id_token,
        session_public_key=session_key.public().to_dict(),
        session_fingerprint=session_fingerprint,
    )


def test_endpoint_tag_restriction_fail(oidc_env: OidcEnv) -> None:
    """Login fails when identity lacks required tag."""
    # Create a tag
    tag_response = oidc_env.sc.create_tag("restricted-tag", "restricted-value")

    # Create auth config with tag restriction
    oidc_auth = oidc_env.sc.create_auth_oidc(
        name="oidc-restricted",
        description="Restricted OIDC",
        tags=[],
        issuer=oidc_env.mock.issuer,
        client_id=oidc_env.mock.client_id,
        client_secret=None,
    )

    # Update auth to require the tag
    oidc_env.sc.update_auth(id=oidc_auth.id, tags=[tag_response])

    # Identity does NOT have the tag
    id_token = oidc_env.mock.issue_token("user@example.com")
    session_key, session_fingerprint = _create_session_key()

    with pytest.raises(pf.client.exceptions.UI):
        oidc_env.sc.oidc_login(
            auth_name="oidc-restricted",
            id_token=id_token,
            session_public_key=session_key.public().to_dict(),
            session_fingerprint=session_fingerprint,
        )


# =============================================================================
# Group B: Full login.oidc_login flow tests (with browser mock)
# =============================================================================


def test_full_oidc_login_flow(oidc_env: OidcEnv, monkeypatch) -> None:
    """Complete OIDC login flow: discovery → PKCE → authorize → callback → token → server login."""

    def fake_browser(url: str) -> None:
        """Simulate browser by making the authorization request in a background thread."""

        def _fetch():
            try:
                requests.get(url, allow_redirects=True, timeout=5)
            except Exception:
                pass  # Ignore errors; we just need to trigger the callback

        threading.Thread(target=_fetch, daemon=True).start()

    monkeypatch.setattr("pf.cli.login.webbrowser.open", fake_browser)

    # Call the full OIDC login flow
    fingerprint = login.oidc_login(oidc_env.config, oidc_env.sc, "oidc-test")
    assert fingerprint  # Should return a session fingerprint
    # The fingerprint is an SSH key fingerprint; it can be used to look up the key in SSH agent
    # In a real CLI, this would be saved to the config file after successful login


def test_full_oidc_login_flow_callback_error(oidc_env: OidcEnv, monkeypatch) -> None:
    """Authorization server rejects the request; callback receives error instead of code."""
    oidc_env.mock.set_authorize_error("access_denied")

    def fake_browser(url: str) -> None:
        """Simulate browser by making the authorization request."""

        def _fetch():
            try:
                requests.get(url, allow_redirects=True, timeout=5)
            except Exception:
                pass

        threading.Thread(target=_fetch, daemon=True).start()

    monkeypatch.setattr("pf.cli.login.webbrowser.open", fake_browser)

    # Should raise because callback never receives a code
    with pytest.raises(pf.client.exceptions.UI, match="did not receive an authorization code"):
        login.oidc_login(oidc_env.config, oidc_env.sc, "oidc-test")
