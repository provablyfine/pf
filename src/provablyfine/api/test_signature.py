import json
import secrets
import time
import types
import typing

import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.hashes
import http_sfv
import provablyfine_client.http_signatures as http_signatures
import provablyfine_client.signer as client_signer
import pytest
import requests
import requests.structures
import starlette.requests

from .. import jwk
from . import responses, signature


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
