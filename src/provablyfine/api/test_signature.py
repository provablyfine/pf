import collections.abc
import contextlib
import json
import pathlib
import secrets
import time
import types
import typing

import cryptography.fernet
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.hashes
import http_sfv
import provablyfine_client.http_signatures as http_signatures
import provablyfine_client.signer as client_signer
import pytest
import requests
import requests.structures
import sqlalchemy
import starlette.requests

from .. import jwk
from . import app_db, migrate, model, responses, signature
from .context import ctx


class _Ed25519Signer(client_signer.Signer):
    def __init__(self, prefix: str, private: jwk.Private) -> None:
        super().__init__(prefix)
        self._private = private

    def thumbprint(self) -> str:
        return self._private.thumbprint()

    def sign(self, data: bytes) -> bytes:
        key = self._private.to_crypto()
        assert isinstance(key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)
        return key.sign(data)


class _EcdsaSigner(client_signer.Signer):
    def __init__(self, prefix: str, private: jwk.Private) -> None:
        super().__init__(prefix)
        self._private = private

    def thumbprint(self) -> str:
        return self._private.thumbprint()

    def sign(self, data: bytes) -> bytes:
        key = self._private.to_crypto()
        assert isinstance(key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey)
        return key.sign(
            data, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256())
        )


def _corrupt_signature(headers: requests.structures.CaseInsensitiveDict[str]) -> None:
    d = http_sfv.Dictionary()
    d.parse(headers["Signature"].encode())
    for label, item in list(d.items()):
        assert isinstance(item, http_sfv.Item)
        corrupted = bytearray(typing.cast(bytes, item.value))
        corrupted[0] ^= 0xFF
        d[label] = http_sfv.Item(bytes(corrupted))
    headers["Signature"] = str(d)


def _app(nonce_store: signature.NonceStore | None = None) -> types.SimpleNamespace:
    return types.SimpleNamespace(state=types.SimpleNamespace(nonce_store=nonce_store or signature.NonceStore()))


def _signed_request_with(
    signer: client_signer.Signer,
    app: types.SimpleNamespace | None = None,
    path: str = "/pf/t/root/whoami",
    body: bytes = b"{}",
    tamper: typing.Callable[[requests.structures.CaseInsensitiveDict[str]], None] | None = None,
) -> tuple[starlette.requests.Request, str]:
    prepared = requests.PreparedRequest()
    prepared.method = "GET"
    prepared.url = f"http://testserver{path}"
    prepared.headers = requests.structures.CaseInsensitiveDict()
    prepared.body = body

    http_signatures.Auth([signer])(prepared)
    if tamper is not None:
        tamper(prepared.headers)

    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in prepared.headers.items()],
        "server": ("testserver", 80),
        "scheme": "http",
        "app": app or _app(),
    }
    request = starlette.requests.Request(scope)
    request.state.body = body
    key_id = f"{signer.prefix()}:{signer.thumbprint()}"
    return request, key_id


def _signed_request(
    key: bytes,
    app: types.SimpleNamespace | None = None,
    path: str = "/pf/t/root/whoami",
    body: bytes = b"{}",
    tamper: typing.Callable[[requests.structures.CaseInsensitiveDict[str]], None] | None = None,
) -> tuple[starlette.requests.Request, str]:
    return _signed_request_with(client_signer.HmacSigner("session", key), app=app, path=path, body=body, tamper=tamper)


def _title(exc: responses.ProblemHTTPException) -> str:
    return json.loads(exc.response.body)["title"]


def _bare_request(headers: list[tuple[bytes, bytes]] | None = None) -> starlette.requests.Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/pf/t/root/whoami",
        "raw_path": b"/pf/t/root/whoami",
        "query_string": b"",
        "headers": headers or [],
        "server": ("testserver", 80),
        "scheme": "http",
        "app": _app(),
    }
    request = starlette.requests.Request(scope)
    request.state.body = b"{}"
    return request


@pytest.fixture
def real_app_db(tmp_path: pathlib.Path) -> collections.abc.Iterator[app_db.AppDb]:
    """A real (sqlite-backed, migrated) AppDb wired into ctx, not a mock.

    Exercises the ctx.app_db/ctx.kek-dependent code paths that a plain unit
    test can't reach, without spawning the subprocess-based e2e API server.
    """
    url = f"sqlite:///{tmp_path / 'tenant.db'}"
    migrate.create_tenant(url)
    engine = sqlalchemy.create_engine(url)
    with engine.connect() as connection:
        db = app_db.create(connection)
        kek = cryptography.fernet.Fernet(cryptography.fernet.Fernet.generate_key())
        with ctx.set_app_db(db), ctx.set_kek(kek):
            yield db


def _seed_identity(name: str = "alice") -> int:
    return model.identity.create(name=name, boundary_id_list=[], tag_id_list=[])


def _seed_account_key(identity_id: int, pub: jwk.Public, is_revoked: bool = False) -> None:
    now = int(time.time())
    ctx.app_db.identity_account_key.create(
        id=pub.thumbprint(),
        public_key=pub.to_dict(),
        identity_id=identity_id,
        created_at=now,
        is_revoked=is_revoked,
        revoked_at=now if is_revoked else None,
    )


def _seed_session_key(
    identity_id: int,
    pub: jwk.Public,
    expires_at: int,
    is_revoked: bool = False,
    role_id: int | None = None,
) -> None:
    now = int(time.time())
    ctx.app_db.identity_session_key.create(
        id=pub.thumbprint(),
        public_key=pub.to_dict(),
        identity_id=identity_id,
        created_at=now,
        is_revoked=is_revoked,
        revoked_at=now if is_revoked else None,
        expires_at=expires_at,
        login_ip=None,
        role_id=role_id,
    )


def _seed_denylisted(key_id: str) -> None:
    # Deliberately not going through model.denylist.create(): that function
    # never sets the row's `id` column and currently raises an IntegrityError
    # against a real (non-mocked) DB — a separate, pre-existing production bug
    # unrelated to what's under test here. Insert directly to isolate this
    # test from that bug rather than silently working around it in production
    # code.
    ctx.app_db.public_key_denylist.create(id=key_id, key_id=key_id, created_at=int(time.time()))


def test_get_keyid_extracts_matching_prefix() -> None:
    key = secrets.token_bytes(32)
    request, key_id = _signed_request(key)
    assert signature._get_keyid(request, "session") == key_id.split(":", 1)[1]


def test_get_keyid_missing_signature_input_header_raises() -> None:
    request = _bare_request()
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature._get_keyid(request, "session")
    assert _title(exc_info.value) == "Missing Signature-Input header"


def test_get_keyid_no_matching_prefix_raises() -> None:
    request, _ = _signed_request(secrets.token_bytes(32))  # signed with the "session" prefix
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature._get_keyid(request, "account")
    assert _title(exc_info.value) == "Missing signature for prefix"


def test_get_keyid_skips_non_matching_label_before_a_match() -> None:
    # A non-matching label sorting first must not short-circuit the search: the
    # loop has to keep scanning past it to reach the label that does match.
    session_signer = client_signer.HmacSigner("session", secrets.token_bytes(32))
    account_priv = jwk.Private.generate_ed25519()
    account_signer = _Ed25519Signer("account", account_priv)
    prepared = requests.PreparedRequest()
    prepared.method = "GET"
    prepared.url = "http://testserver/pf/t/root/whoami"
    prepared.headers = requests.structures.CaseInsensitiveDict()
    prepared.body = b"{}"
    http_signatures.Auth([session_signer, account_signer])(prepared)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/pf/t/root/whoami",
        "raw_path": b"/pf/t/root/whoami",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in prepared.headers.items()],
        "server": ("testserver", 80),
        "scheme": "http",
        "app": _app(),
    }
    request = starlette.requests.Request(scope)
    request.state.body = b"{}"
    assert signature._get_keyid(request, "account") == account_priv.public().thumbprint()


def test_valid_signature_is_accepted() -> None:
    key = secrets.token_bytes(32)
    request, key_id = _signed_request(key)
    signature.verify(request, key_id=key_id, key=jwk.Symmetric.from_bytes(key))


def test_replayed_signature_is_rejected() -> None:
    key = secrets.token_bytes(32)
    app = _app()
    request, key_id = _signed_request(key, app=app)
    jwk_key = jwk.Symmetric.from_bytes(key)

    signature.verify(request, key_id=key_id, key=jwk_key)

    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature.verify(request, key_id=key_id, key=jwk_key)
    assert _title(exc_info.value) == "Signature nonce has already been used"


def test_same_nonce_from_different_key_id_is_not_a_replay() -> None:
    app = _app()
    key1 = secrets.token_bytes(32)
    key2 = secrets.token_bytes(32)

    real_token_hex = http_signatures.secrets.token_hex
    http_signatures.secrets.token_hex = lambda nbytes=None: "fixed-nonce"
    try:
        request1, key_id1 = _signed_request(key1, app=app)
        request2, key_id2 = _signed_request(key2, app=app)
    finally:
        http_signatures.secrets.token_hex = real_token_hex
    assert key_id1 != key_id2

    signature.verify(request1, key_id=key_id1, key=jwk.Symmetric.from_bytes(key1))
    signature.verify(request2, key_id=key_id2, key=jwk.Symmetric.from_bytes(key2))


def test_two_signatures_from_same_key_with_different_nonces_are_both_accepted() -> None:
    key = secrets.token_bytes(32)
    app = _app()
    jwk_key = jwk.Symmetric.from_bytes(key)
    request1, key_id = _signed_request(key, app=app)
    request2, _ = _signed_request(key, app=app)

    signature.verify(request1, key_id=key_id, key=jwk_key)
    signature.verify(request2, key_id=key_id, key=jwk_key)


def test_old_signature_is_rejected() -> None:
    key = secrets.token_bytes(32)
    stale_time = int(time.time()) - signature.FRESHNESS_WINDOW_SECONDS - 1
    real_time = time.time
    time.time = lambda: stale_time
    try:
        request, key_id = _signed_request(key)
    finally:
        time.time = real_time

    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature.verify(request, key_id=key_id, key=jwk.Symmetric.from_bytes(key))
    assert _title(exc_info.value) == "Signature is too old"


def test_nonce_store_rejects_duplicate_within_window() -> None:
    store = signature.NonceStore(window_seconds=300)
    assert store.check_and_add("k1", "n1", now=1000)
    assert not store.check_and_add("k1", "n1", now=1100)
    assert store.check_and_add("k1", "n2", now=1100)
    assert store.check_and_add("k2", "n1", now=1100)


def test_nonce_store_forgets_entries_after_window() -> None:
    store = signature.NonceStore(window_seconds=300)
    assert store.check_and_add("k1", "n1", now=1000)
    assert store.check_and_add("k1", "n1", now=1301)


def test_nonce_store_does_not_forget_entries_exactly_at_window_boundary() -> None:
    store = signature.NonceStore(window_seconds=300)
    assert store.check_and_add("k1", "n1", now=1000)
    assert not store.check_and_add("k1", "n1", now=1300)


def test_signature_exactly_at_freshness_window_is_accepted() -> None:
    key = secrets.token_bytes(32)
    created_time = 1_700_000_000
    real_time = time.time
    time.time = lambda: created_time
    try:
        request, key_id = _signed_request(key)
        time.time = lambda: created_time + signature.FRESHNESS_WINDOW_SECONDS
        signature.verify(request, key_id=key_id, key=jwk.Symmetric.from_bytes(key))
    finally:
        time.time = real_time


def test_signature_one_second_past_freshness_window_is_rejected() -> None:
    key = secrets.token_bytes(32)
    created_time = 1_700_000_000
    real_time = time.time
    time.time = lambda: created_time
    try:
        request, key_id = _signed_request(key)
        time.time = lambda: created_time + signature.FRESHNESS_WINDOW_SECONDS + 1
        with pytest.raises(responses.ProblemHTTPException) as exc_info:
            signature.verify(request, key_id=key_id, key=jwk.Symmetric.from_bytes(key))
        assert _title(exc_info.value) == "Signature is too old"
    finally:
        time.time = real_time


def test_tampered_signature_is_rejected() -> None:
    key = secrets.token_bytes(32)
    request, key_id = _signed_request(key, tamper=_corrupt_signature)
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature.verify(request, key_id=key_id, key=jwk.Symmetric.from_bytes(key))
    assert _title(exc_info.value) == "Invalid signature"


def test_ed25519_signature_is_accepted() -> None:
    private = jwk.Private.generate_ed25519()
    request, key_id = _signed_request_with(_Ed25519Signer("session", private))
    signature.verify(request, key_id=key_id, key=private.public())


def test_ed25519_tampered_signature_is_rejected() -> None:
    private = jwk.Private.generate_ed25519()
    request, key_id = _signed_request_with(_Ed25519Signer("session", private), tamper=_corrupt_signature)
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature.verify(request, key_id=key_id, key=private.public())
    assert _title(exc_info.value) == "Invalid signature"


def test_ecdsa_signature_is_accepted() -> None:
    private = jwk.Private.generate_ecdsa_nistp256()
    request, key_id = _signed_request_with(_EcdsaSigner("session", private))
    signature.verify(request, key_id=key_id, key=private.public())


def test_ecdsa_tampered_signature_is_rejected() -> None:
    private = jwk.Private.generate_ecdsa_nistp256()
    request, key_id = _signed_request_with(_EcdsaSigner("session", private), tamper=_corrupt_signature)
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature.verify(request, key_id=key_id, key=private.public())
    assert _title(exc_info.value) == "Invalid signature"


def test_unsupported_key_type_is_rejected() -> None:
    key = secrets.token_bytes(32)
    request, key_id = _signed_request(key)
    unsupported_key = jwk.Private.generate_ecdsa_nistp384().public()
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        signature.verify(request, key_id=key_id, key=unsupported_key)
    assert _title(exc_info.value) == "Unsupported key type"


@pytest.mark.anyio
async def test_verify_account_accepts_valid_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    _seed_account_key(identity_id, priv.public())
    request, _ = _signed_request_with(_Ed25519Signer("account", priv))
    async with contextlib.aclosing(signature.verify_account(request)) as agen:
        await agen.__anext__()
        assert ctx.identity_id == identity_id


@pytest.mark.anyio
async def test_verify_account_rejects_unknown_key(real_app_db: app_db.AppDb) -> None:
    priv = jwk.Private.generate_ed25519()
    request, _ = _signed_request_with(_Ed25519Signer("account", priv))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_account(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Account does not exist"


@pytest.mark.anyio
async def test_verify_account_rejects_revoked_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    _seed_account_key(identity_id, priv.public(), is_revoked=True)
    request, _ = _signed_request_with(_Ed25519Signer("account", priv))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_account(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Account key is revoked"


@pytest.mark.anyio
async def test_verify_account_rejects_denylisted_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    pub = priv.public()
    _seed_account_key(identity_id, pub)
    _seed_denylisted(pub.thumbprint())
    request, _ = _signed_request_with(_Ed25519Signer("account", priv))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_account(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Unable to use key"


@pytest.mark.anyio
async def test_verify_session_accepts_valid_key_and_sets_role(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    _seed_session_key(identity_id, priv.public(), expires_at=int(time.time()) + 3600, role_id=42)
    request, _ = _signed_request_with(_Ed25519Signer("session", priv))
    async with contextlib.aclosing(signature.verify_session(request)) as agen:
        await agen.__anext__()
        assert ctx.identity_id == identity_id
        assert ctx.active_role_id == 42
        assert ctx.session_key_id == priv.public().thumbprint()


@pytest.mark.anyio
async def test_verify_session_rejects_unknown_key(real_app_db: app_db.AppDb) -> None:
    priv = jwk.Private.generate_ed25519()
    request, _ = _signed_request_with(_Ed25519Signer("session", priv))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_session(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Session does not exist"


@pytest.mark.anyio
async def test_verify_session_rejects_revoked_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    _seed_session_key(identity_id, priv.public(), expires_at=int(time.time()) + 3600, is_revoked=True)
    request, _ = _signed_request_with(_Ed25519Signer("session", priv))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_session(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Session key is revoked"


@pytest.mark.anyio
async def test_verify_session_rejects_denylisted_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    pub = priv.public()
    _seed_session_key(identity_id, pub, expires_at=int(time.time()) + 3600)
    _seed_denylisted(pub.thumbprint())
    request, _ = _signed_request_with(_Ed25519Signer("session", priv))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_session(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Unable to use key"


@pytest.mark.anyio
async def test_verify_session_rejects_expired_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    _seed_session_key(identity_id, priv.public(), expires_at=int(time.time()) - 1)
    request, _ = _signed_request_with(_Ed25519Signer("session", priv))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_session(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Session key is expired"


@pytest.mark.anyio
async def test_verify_session_rejects_key_expiring_exactly_now(
    real_app_db: app_db.AppDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity_id = _seed_identity()
    priv = jwk.Private.generate_ed25519()
    expires_at = int(time.time()) + 1000
    _seed_session_key(identity_id, priv.public(), expires_at=expires_at)
    request, _ = _signed_request_with(_Ed25519Signer("session", priv))
    monkeypatch.setattr(signature.time, "time", lambda: float(expires_at))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_session(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Session key is expired"


@pytest.mark.anyio
async def test_verify_invitation_accepts_valid_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    invitation_id = model.identity_invitation_key.create(identity_id=identity_id, expiration_delay_s=3600)
    invitation = model.identity_invitation_key.read(invitation_id)
    assert invitation is not None
    request, _ = _signed_request_with(client_signer.HmacSigner("invitation", invitation.key.to_bytes()))
    async with contextlib.aclosing(signature.verify_invitation(request)) as agen:
        result = await agen.__anext__()
        assert result.identity_id == identity_id
        assert ctx.identity_id == identity_id


@pytest.mark.anyio
async def test_verify_invitation_rejects_unknown_key(real_app_db: app_db.AppDb) -> None:
    key = jwk.Symmetric.generate()
    request, _ = _signed_request_with(client_signer.HmacSigner("invitation", key.to_bytes()))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_invitation(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Invitation does not exist"


@pytest.mark.anyio
async def test_verify_invitation_rejects_revoked_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    invitation_id = model.identity_invitation_key.create(identity_id=identity_id, expiration_delay_s=3600)
    ctx.app_db.identity_invitation_key.update(is_revoked=True).where(id=invitation_id)
    invitation = model.identity_invitation_key.read(invitation_id)
    assert invitation is not None
    request, _ = _signed_request_with(client_signer.HmacSigner("invitation", invitation.key.to_bytes()))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_invitation(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Invitation is revoked"


@pytest.mark.anyio
async def test_verify_invitation_rejects_expired_key(real_app_db: app_db.AppDb) -> None:
    identity_id = _seed_identity()
    invitation_id = model.identity_invitation_key.create(identity_id=identity_id, expiration_delay_s=-1)
    invitation = model.identity_invitation_key.read(invitation_id)
    assert invitation is not None
    request, _ = _signed_request_with(client_signer.HmacSigner("invitation", invitation.key.to_bytes()))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_invitation(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Invitation is expired"


@pytest.mark.anyio
async def test_verify_invitation_rejects_key_expiring_exactly_now(
    real_app_db: app_db.AppDb, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity_id = _seed_identity()
    invitation_id = model.identity_invitation_key.create(identity_id=identity_id, expiration_delay_s=1000)
    invitation = model.identity_invitation_key.read(invitation_id)
    assert invitation is not None
    request, _ = _signed_request_with(client_signer.HmacSigner("invitation", invitation.key.to_bytes()))
    monkeypatch.setattr(signature.time, "time", lambda: float(invitation.expires_at))
    with pytest.raises(responses.ProblemHTTPException) as exc_info:
        async with contextlib.aclosing(signature.verify_invitation(request)) as agen:
            await agen.__anext__()
    assert _title(exc_info.value) == "Invitation is expired"
