"""OIDC login e2e tests."""

import asyncio
import dataclasses
import json
import threading
import time
import typing

import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.hashes
import provablyfine_client as pfc
import pytest

import provablyfine.browser_login
import provablyfine.cli.login
import provablyfine.client
import provablyfine.jwk
import provablyfine.ssh.agent

from . import mock_oidc


def _create_session_key() -> provablyfine.jwk.Private:
    """Create a session key for use as a direct in-memory signer.

    This allows us to make sure we do not use the oracle for signing
    so these tests exercise only the oidc part.
    """
    return provablyfine.jwk.Private.generate_ed25519()


@dataclasses.dataclass
class OidcEnv:
    """Test environment with OIDC setup."""

    config: provablyfine.client.Config
    sc: provablyfine.client.Factory
    mock: mock_oidc.MockOidcProvider


@pytest.fixture
def oidc_env(api, mock_oidc, tmp_path) -> typing.Iterator[OidcEnv]:
    """Set up OIDC test environment: tenant initialized, auth config, identity."""
    # Write temporary account key file
    account_key_obj = provablyfine.jwk.Private.generate_ed25519()
    account_key_file = tmp_path / "account_key"
    account_key_file.write_bytes(account_key_obj.to_pem())

    # Initialize Config pointing to the API (no session key yet)
    config = provablyfine.client.Config(
        directory_url=f"http://127.0.0.1:{api.port}/pf/t/00000000-0000-0000-0000-000000000001/directory",
        account_key_file=str(account_key_file),
    )

    # Create factory and initialize tenant
    sc = provablyfine.client.Factory(config)
    sc.invitation(sc.public().initialize(), str(account_key_file)).accept_invitation()

    # Generate session key and login via http_sig
    session_key_obj = provablyfine.jwk.Private.generate_ed25519()
    session_key_file = tmp_path / "session_key"
    session_key_file.write_bytes(session_key_obj.to_pem())
    session_fingerprint = str(session_key_file)  # Full path for http_sig_login

    result = sc.account(str(account_key_file), session_fingerprint).login_http_sig(session_key_obj.public().to_dict())
    if result.roles:
        sc.session_with_private_key(session_key_obj).update_session(result.roles[0].id)

    # Update config to include session key so subsequent calls work
    config = provablyfine.client.Config(
        directory_url=config.directory_url,
        account_key_file=config.account_key_file,
        session_key_file=str(session_key_file),
    )
    sc = provablyfine.client.Factory(config)

    # Create OIDC auth config pointing to mock OIDC provider
    sc.session().create_auth_oidc(
        name="oidc-test",
        client_type="cli",
        description="Test OIDC provider",
        issuer=mock_oidc.issuer,
        client_id=mock_oidc.client_id,
        client_secret=None,
    )

    # Create identity with email matching the mock token
    sc.session().create_identity(
        name="user@example.com",
        boundary_id_list=[],
        boundary_name_list=[],
        tag_id_list=[],
        tag_name_value_list=[],
    )

    yield OidcEnv(config=config, sc=sc, mock=mock_oidc)


# =============================================================================
# Server endpoint tests (call login_oidc directly)
# =============================================================================


def test_endpoint_rs256(oidc_env: OidcEnv) -> None:
    """Valid RS256 token succeeds."""
    nonce = "test-nonce-rs256"
    id_token = oidc_env.mock.issue_token("user@example.com", alg="RS256", nonce=nonce)
    session_key = _create_session_key()

    oidc_env.sc.session_with_private_key(session_key).login_oidc(
        auth_name="oidc-test",
        client_type="cli",
        id_token=id_token,
        nonce=nonce,
        session_public_key=session_key.public().to_dict(),
    )


def test_slow_identity_provider_does_not_block_other_writes(oidc_env: OidcEnv) -> None:
    """The identity provider is called before the transaction starts, so it cannot hold the tenant write lock."""
    nonce = "test-nonce-slow"
    id_token = oidc_env.mock.issue_token("user@example.com", alg="RS256", nonce=nonce)
    session_key = _create_session_key()
    oidc_env.mock.delay_s = 1.5

    login = threading.Thread(
        target=lambda: (
            provablyfine.client.Factory(oidc_env.config, timeout=30)
            .session_with_private_key(session_key)
            .login_oidc(
                auth_name="oidc-test",
                client_type="cli",
                id_token=id_token,
                nonce=nonce,
                session_public_key=session_key.public().to_dict(),
            )
        )
    )
    login.start()
    try:
        time.sleep(0.5)  # the login is now waiting for the identity provider
        assert login.is_alive()
        started = time.monotonic()
        oidc_env.sc.session().create_tag("written-during-login", "yes")
        assert time.monotonic() - started < 1.0, "a write waited for the identity provider"
    finally:
        login.join(30)
    assert not login.is_alive()


def test_oidc_login_is_audited(oidc_env: OidcEnv) -> None:
    """The session table is not the only record of a login."""
    nonce = "test-nonce-audit"
    id_token = oidc_env.mock.issue_token("user@example.com", alg="RS256", nonce=nonce)
    session_key = _create_session_key()

    oidc_env.sc.session_with_private_key(session_key).login_oidc(
        auth_name="oidc-test",
        client_type="cli",
        id_token=id_token,
        nonce=nonce,
        session_public_key=session_key.public().to_dict(),
    )

    sc = oidc_env.sc.session()
    user_id = next(i.id for i in sc.list_identities().identities if i.name == "user@example.com")
    (entry,) = [
        e for e in sc.list_audit_log().entries if e.type == "session-create" and e.details["identity_id"] == user_id
    ]
    assert entry.details["method"] == "oidc"
    assert entry.details["session_key_id"] == session_key.public().thumbprint()
    assert entry.details["login_ip"] == "127.0.0.1"


def test_endpoint_es256(oidc_env: OidcEnv) -> None:
    """Valid ES256 token succeeds."""
    nonce = "test-nonce-es256"
    id_token = oidc_env.mock.issue_token("user@example.com", alg="ES256", nonce=nonce)
    session_key = _create_session_key()

    oidc_env.sc.session_with_private_key(session_key).login_oidc(
        auth_name="oidc-test",
        client_type="cli",
        id_token=id_token,
        nonce=nonce,
        session_public_key=session_key.public().to_dict(),
    )


def test_endpoint_expired(oidc_env: OidcEnv) -> None:
    """Expired token is rejected."""
    id_token = oidc_env.mock.issue_token("user@example.com", expired=True)
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_not_yet_valid(oidc_env: OidcEnv) -> None:
    """Token with nbf in the future is rejected."""
    id_token = oidc_env.mock.issue_token("user@example.com", nbf=int(time.time()) + 3600)
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_wrong_issuer(oidc_env: OidcEnv) -> None:
    """Token with wrong issuer is rejected."""
    id_token = oidc_env.mock.issue_token("user@example.com", issuer="https://evil.example.com")
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_wrong_audience(oidc_env: OidcEnv) -> None:
    """Token with wrong audience is rejected, and the response does not leak why."""
    id_token = oidc_env.mock.issue_token("user@example.com", audience="wrong-client")
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI) as excinfo:
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )
    assert "OIDC token verification failed" in str(excinfo.value)
    assert "audience mismatch" not in str(excinfo.value)


def test_endpoint_email_not_verified(oidc_env: OidcEnv) -> None:
    """Token with email_verified=false is rejected."""
    id_token = oidc_env.mock.issue_token("user@example.com", nonce="irrelevant", email_verified=False)
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_email_verified_missing_rejected_by_default(oidc_env: OidcEnv) -> None:
    """Token without an email_verified claim is rejected when the auth config requires it (the default)."""
    id_token = oidc_env.mock.issue_token("user@example.com", nonce="irrelevant", email_verified=None)
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_email_verified_absent_allowed_when_opted_out(oidc_env: OidcEnv) -> None:
    """A missing email_verified claim is tolerated on an auth config that opted out of requiring it."""
    oidc_env.sc.session().create_auth_oidc(
        name="oidc-test-opt-out",
        client_type="cli",
        description="Test OIDC provider without email_verified",
        issuer=oidc_env.mock.issuer,
        client_id=oidc_env.mock.client_id,
        client_secret=None,
        require_email_verified=False,
    )
    id_token = oidc_env.mock.issue_token("user@example.com", nonce="irrelevant", email_verified=None)
    session_key = _create_session_key()

    oidc_env.sc.session_with_private_key(session_key).login_oidc(
        auth_name="oidc-test-opt-out",
        client_type="cli",
        id_token=id_token,
        nonce="irrelevant",
        session_public_key=session_key.public().to_dict(),
    )


def test_endpoint_email_explicitly_unverified_rejected_even_when_opted_out(oidc_env: OidcEnv) -> None:
    """An explicit email_verified=false is never tolerated, even when the auth config opted out."""
    oidc_env.sc.session().create_auth_oidc(
        name="oidc-test-opt-out",
        client_type="cli",
        description="Test OIDC provider without email_verified",
        issuer=oidc_env.mock.issuer,
        client_id=oidc_env.mock.client_id,
        client_secret=None,
        require_email_verified=False,
    )
    id_token = oidc_env.mock.issue_token("user@example.com", nonce="irrelevant", email_verified=False)
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test-opt-out",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_email_verified_string_rejected_even_when_opted_out(oidc_env: OidcEnv) -> None:
    """A non-boolean email_verified (a string, as some non-compliant providers send) is always rejected."""
    oidc_env.sc.session().create_auth_oidc(
        name="oidc-test-opt-out",
        client_type="cli",
        description="Test OIDC provider without email_verified",
        issuer=oidc_env.mock.issuer,
        client_id=oidc_env.mock.client_id,
        client_secret=None,
        require_email_verified=False,
    )
    id_token = oidc_env.mock.issue_token("user@example.com", nonce="irrelevant", email_verified="true")
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test-opt-out",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_require_email_verified_can_be_updated(oidc_env: OidcEnv) -> None:
    """An existing auth config can be switched to not require email_verified, without deleting it."""
    sc = oidc_env.sc.session()
    created = sc.create_auth_oidc(
        name="oidc-test-updatable",
        client_type="cli",
        description="Test OIDC provider",
        issuer=oidc_env.mock.issuer,
        client_id=oidc_env.mock.client_id,
        client_secret=None,
    )

    id_token = oidc_env.mock.issue_token("user@example.com", nonce="before-update", email_verified=None)
    session_key = _create_session_key()
    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test-updatable",
            client_type="cli",
            id_token=id_token,
            nonce="before-update",
            session_public_key=session_key.public().to_dict(),
        )

    sc.update_auth(created.id, require_email_verified=False)

    id_token_2 = oidc_env.mock.issue_token("user@example.com", nonce="after-update", email_verified=None)
    session_key_2 = _create_session_key()
    oidc_env.sc.session_with_private_key(session_key_2).login_oidc(
        auth_name="oidc-test-updatable",
        client_type="cli",
        id_token=id_token_2,
        nonce="after-update",
        session_public_key=session_key_2.public().to_dict(),
    )

    (entry,) = [e for e in sc.list_audit_log().entries if e.type == "auth-update" and e.details.get("id") == created.id]
    assert entry.details["require_email_verified"] is False


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

    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_missing_kid(oidc_env: OidcEnv) -> None:
    """Token without a kid in its header is rejected rather than validated against a random JWK."""
    id_token = oidc_env.mock.issue_token("user@example.com", alg="RS256", no_kid=True)
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_unknown_auth(oidc_env: OidcEnv) -> None:
    """Login with unknown auth config fails."""
    id_token = oidc_env.mock.issue_token("user@example.com")
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="no-such-auth",
            client_type="cli",
            id_token=id_token,
            nonce="irrelevant",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_missing_nonce(oidc_env: OidcEnv) -> None:
    """Token without nonce claim is rejected."""
    id_token = oidc_env.mock.issue_token("user@example.com")
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="some-nonce",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_wrong_nonce(oidc_env: OidcEnv) -> None:
    """Token whose nonce does not match the submitted nonce is rejected."""
    id_token = oidc_env.mock.issue_token("user@example.com", nonce="real-nonce")
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce="wrong-nonce",
            session_public_key=session_key.public().to_dict(),
        )


def test_endpoint_replay_nonce(oidc_env: OidcEnv) -> None:
    """Replaying the same id_token with the same nonce is rejected on the second attempt."""
    nonce = "replay-test-nonce"
    id_token = oidc_env.mock.issue_token("user@example.com", nonce=nonce)
    session_key1 = _create_session_key()

    oidc_env.sc.session_with_private_key(session_key1).login_oidc(
        auth_name="oidc-test",
        client_type="cli",
        id_token=id_token,
        nonce=nonce,
        session_public_key=session_key1.public().to_dict(),
    )

    session_key2 = _create_session_key()
    with pytest.raises(pfc.exceptions.UI):
        oidc_env.sc.session_with_private_key(session_key2).login_oidc(
            auth_name="oidc-test",
            client_type="cli",
            id_token=id_token,
            nonce=nonce,
            session_public_key=session_key2.public().to_dict(),
        )


# =============================================================================
# Device code flow tests
# =============================================================================


@dataclasses.dataclass
class OidcDeviceCodeEnv:
    """Test environment with oidc-device-code auth config."""

    config: provablyfine.client.Config
    sc: provablyfine.client.Factory
    mock: mock_oidc.MockOidcProvider


@pytest.fixture
def oidc_device_code_env(api, mock_oidc, tmp_path) -> typing.Iterator[OidcDeviceCodeEnv]:
    """Set up oidc-device-code test environment."""
    account_key_obj = provablyfine.jwk.Private.generate_ed25519()
    account_key_file = tmp_path / "account_key"
    account_key_file.write_bytes(account_key_obj.to_pem())

    config = provablyfine.client.Config(
        directory_url=f"http://127.0.0.1:{api.port}/pf/t/00000000-0000-0000-0000-000000000001/directory",
        account_key_file=str(account_key_file),
    )

    sc = provablyfine.client.Factory(config)
    sc.invitation(sc.public().initialize(), str(account_key_file)).accept_invitation()

    session_key_obj = provablyfine.jwk.Private.generate_ed25519()
    session_key_file = tmp_path / "session_key"
    session_key_file.write_bytes(session_key_obj.to_pem())
    session_fingerprint = str(session_key_file)

    result = sc.account(str(account_key_file), session_fingerprint).login_http_sig(session_key_obj.public().to_dict())
    if result.roles:
        sc.session_with_private_key(session_key_obj).update_session(result.roles[0].id)

    config = provablyfine.client.Config(
        directory_url=config.directory_url,
        account_key_file=config.account_key_file,
        session_key_file=str(session_key_file),
    )
    sc = provablyfine.client.Factory(config)

    sc.session().create_auth_oidc_device_code(
        name="oidc-dc-test",
        client_type="cli",
        description="Test OIDC device code provider",
        issuer=mock_oidc.issuer,
        client_id=mock_oidc.client_id,
    )

    sc.session().create_identity(
        name="user@example.com",
        boundary_id_list=[],
        boundary_name_list=[],
        tag_id_list=[],
        tag_name_value_list=[],
    )

    yield OidcDeviceCodeEnv(config=config, sc=sc, mock=mock_oidc)


def test_device_code_endpoint_success(oidc_device_code_env: OidcDeviceCodeEnv) -> None:
    """Server endpoint accepts oidc-device-code auth config type."""
    nonce = "test-nonce-device-code"
    id_token = oidc_device_code_env.mock.issue_token("user@example.com", alg="RS256", nonce=nonce)
    session_key = _create_session_key()

    oidc_device_code_env.sc.session_with_private_key(session_key).login_oidc(
        auth_name="oidc-dc-test",
        client_type="cli",
        id_token=id_token,
        nonce=nonce,
        session_public_key=session_key.public().to_dict(),
    )


def test_device_code_endpoint_expired_token(oidc_device_code_env: OidcDeviceCodeEnv) -> None:
    """Expired token is rejected for oidc-device-code auth config."""
    nonce = "test-nonce-expired"
    id_token = oidc_device_code_env.mock.issue_token("user@example.com", alg="RS256", expired=True, nonce=nonce)
    session_key = _create_session_key()

    with pytest.raises(pfc.exceptions.UI, match="Unable to login via OIDC"):
        oidc_device_code_env.sc.session_with_private_key(session_key).login_oidc(
            auth_name="oidc-dc-test",
            client_type="cli",
            id_token=id_token,
            nonce=nonce,
            session_public_key=session_key.public().to_dict(),
        )


@pytest.mark.real_session_oracle
def test_full_device_code_login_flow(oidc_device_code_env: OidcDeviceCodeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    """Complete device code login flow: device auth → poll → user completes → token → server login."""
    _finish_device_code_login(
        oidc_device_code_env.config, oidc_device_code_env.sc, "oidc-dc-test", oidc_device_code_env.mock, monkeypatch
    )


def _finish_device_code_login(
    config: provablyfine.client.Config,
    sc: provablyfine.client.Factory,
    auth_name: str,
    mock: mock_oidc.MockOidcProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    """Run a device code login, approve the code it asks for, and return the session key fingerprint."""
    monkeypatch.setattr("provablyfine.browser_login.open_browser", lambda url: None)
    result: list[str] = []
    error: list[Exception] = []

    def _run_login() -> None:
        try:
            provablyfine.cli.login.oidc_device_code_login(config, sc, auth_name)
            fp = config.session_key_fingerprint
            if fp:
                result.append(fp)
        except Exception as e:
            error.append(e)

    login_thread = threading.Thread(target=_run_login, daemon=True)
    login_thread.start()

    # Wait for device code to be issued, then simulate user completing auth
    deadline = time.time() + 10
    device_code = None
    while time.time() < deadline:
        if mock._pending_device_codes:
            device_code = next(iter(mock._pending_device_codes))
            break
        time.sleep(0.05)

    assert device_code is not None, "Device code not issued within timeout"
    mock.complete_device_auth(device_code)

    login_thread.join(timeout=10)
    assert not error, f"Login failed: {error[0]}"
    assert result, "Login did not return a session fingerprint"
    return result[0]


# =============================================================================
# Device code flow with a client secret
# =============================================================================


_DEVICE_CLIENT_SECRET = "device-client-secret"


@dataclasses.dataclass
class OidcSecretDeviceCodeEnv:
    """Test environment with oidc-secret-device-code auth config."""

    config: provablyfine.client.Config
    sc: provablyfine.client.Factory
    mock: mock_oidc.MockOidcProvider


@pytest.fixture
def oidc_secret_device_code_env(api, mock_oidc, tmp_path) -> typing.Iterator[OidcSecretDeviceCodeEnv]:
    """Set up oidc-secret-device-code test environment, against a provider that demands a secret."""
    mock_oidc.client_secret = _DEVICE_CLIENT_SECRET

    account_key_obj = provablyfine.jwk.Private.generate_ed25519()
    account_key_file = tmp_path / "account_key"
    account_key_file.write_bytes(account_key_obj.to_pem())

    config = provablyfine.client.Config(
        directory_url=f"http://127.0.0.1:{api.port}/pf/t/00000000-0000-0000-0000-000000000001/directory",
        account_key_file=str(account_key_file),
    )

    sc = provablyfine.client.Factory(config)
    sc.invitation(sc.public().initialize(), str(account_key_file)).accept_invitation()

    session_key_obj = provablyfine.jwk.Private.generate_ed25519()
    session_key_file = tmp_path / "session_key"
    session_key_file.write_bytes(session_key_obj.to_pem())
    session_fingerprint = str(session_key_file)

    result = sc.account(str(account_key_file), session_fingerprint).login_http_sig(session_key_obj.public().to_dict())
    if result.roles:
        sc.session_with_private_key(session_key_obj).update_session(result.roles[0].id)

    config = provablyfine.client.Config(
        directory_url=config.directory_url,
        account_key_file=config.account_key_file,
        session_key_file=str(session_key_file),
    )
    sc = provablyfine.client.Factory(config)

    sc.session().create_auth_oidc_secret_device_code(
        name="oidc-sdc-test",
        client_type="cli",
        description="Test OIDC device code provider that requires a client secret",
        issuer=mock_oidc.issuer,
        client_id=mock_oidc.client_id,
        client_secret=_DEVICE_CLIENT_SECRET,
    )

    sc.session().create_identity(
        name="user@example.com",
        boundary_id_list=[],
        boundary_name_list=[],
        tag_id_list=[],
        tag_name_value_list=[],
    )

    yield OidcSecretDeviceCodeEnv(config=config, sc=sc, mock=mock_oidc)


def test_secret_device_code_endpoint_success(oidc_secret_device_code_env: OidcSecretDeviceCodeEnv) -> None:
    """Server endpoint accepts oidc-secret-device-code auth config type."""
    nonce = "test-nonce-secret-device-code"
    id_token = oidc_secret_device_code_env.mock.issue_token("user@example.com", alg="RS256", nonce=nonce)
    session_key = _create_session_key()

    oidc_secret_device_code_env.sc.session_with_private_key(session_key).login_oidc(
        auth_name="oidc-sdc-test",
        client_type="cli",
        id_token=id_token,
        nonce=nonce,
        session_public_key=session_key.public().to_dict(),
    )


@pytest.mark.real_session_oracle
def test_full_secret_device_code_login_flow(
    oidc_secret_device_code_env: OidcSecretDeviceCodeEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The secret is sent to the provider, which is what lets the flow complete."""
    _finish_device_code_login(
        oidc_secret_device_code_env.config,
        oidc_secret_device_code_env.sc,
        "oidc-sdc-test",
        oidc_secret_device_code_env.mock,
        monkeypatch,
    )


@pytest.mark.real_session_oracle
def test_device_code_flow_fails_without_the_secret(
    oidc_secret_device_code_env: OidcSecretDeviceCodeEnv, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A provider that requires client authentication rejects a config that sends no secret."""
    oidc_secret_device_code_env.sc.session().create_auth_oidc_device_code(
        name="oidc-dc-no-secret",
        client_type="cli",
        description="Same provider, no client secret",
        issuer=oidc_secret_device_code_env.mock.issuer,
        client_id=oidc_secret_device_code_env.mock.client_id,
    )
    monkeypatch.setattr("provablyfine.browser_login.open_browser", lambda url: None)

    with pytest.raises(pfc.exceptions.UI, match="Device authorization failed"):
        provablyfine.cli.login.oidc_device_code_login(
            oidc_secret_device_code_env.config, oidc_secret_device_code_env.sc, "oidc-dc-no-secret"
        )


def test_public_secret_device_code_config_keeps_the_secret(
    oidc_secret_device_code_env: OidcSecretDeviceCodeEnv,
) -> None:
    """The cli must learn the secret from the public config, or it cannot run the flow."""
    auth_public = oidc_secret_device_code_env.sc.public().get_public_auth("oidc-sdc-test", "cli")
    assert isinstance(auth_public.config, pfc.schemas.OidcSecretDeviceCodeConfig)
    assert auth_public.config.client_secret == _DEVICE_CLIENT_SECRET


def test_device_code_config_rejects_a_secret(oidc_secret_device_code_env: OidcSecretDeviceCodeEnv) -> None:
    """oidc-device-code has no client_secret. Sending one is a contract violation, not a silent drop."""
    http = provablyfine.client.Client(oidc_secret_device_code_env.config).session_auth(
        oidc_secret_device_code_env.config.session_key_file
    )
    with pytest.raises(pfc.exceptions.UI, match="Extra inputs are not permitted"):
        http.post(
            url=http.directory.auth,
            json={
                "name": "oidc-dc-with-secret",
                "client_type": "cli",
                "description": "",
                "config": {
                    "type": "oidc-device-code",
                    "issuer": oidc_secret_device_code_env.mock.issuer,
                    "client_id": oidc_secret_device_code_env.mock.client_id,
                    "client_secret": _DEVICE_CLIENT_SECRET,
                },
            },
        )


def test_secret_device_code_config_requires_a_client_type_of_cli(
    oidc_secret_device_code_env: OidcSecretDeviceCodeEnv,
) -> None:
    """A web client would receive the secret, so the type is refused for it."""
    http = provablyfine.client.Client(oidc_secret_device_code_env.config).session_auth(
        oidc_secret_device_code_env.config.session_key_file
    )
    with pytest.raises(pfc.exceptions.UI, match="requires client_type cli"):
        http.post(
            url=http.directory.auth,
            json={
                "name": "oidc-sdc-web",
                "client_type": "web",
                "description": "",
                "config": {
                    "type": "oidc-secret-device-code",
                    "issuer": oidc_secret_device_code_env.mock.issuer,
                    "client_id": oidc_secret_device_code_env.mock.client_id,
                    "client_secret": _DEVICE_CLIENT_SECRET,
                },
            },
        )


def test_async_client_creates_both_device_code_types(oidc_device_code_env: OidcDeviceCodeEnv) -> None:
    """The TUI creates auth configs through the async client, on both device code types."""
    env = oidc_device_code_env

    async def _create() -> list[str]:
        sc = env.sc.async_session()
        plain = await sc.create_auth_oidc_device_code("async-device", "cli", "", env.mock.issuer, env.mock.client_id)
        secret = await sc.create_auth_oidc_secret_device_code(
            "async-device-secret", "cli", "", env.mock.issuer, env.mock.client_id, _DEVICE_CLIENT_SECRET
        )
        return [plain.config.type, secret.config.type]

    assert asyncio.run(_create()) == ["oidc-device-code", "oidc-secret-device-code"]
