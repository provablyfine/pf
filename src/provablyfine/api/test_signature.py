import json
import secrets
import time
import types

import provablyfine_client.http_signatures as http_signatures
import provablyfine_client.signer as client_signer
import pytest
import requests
import requests.structures
import starlette.requests

from .. import jwk
from . import responses, signature


def _app(nonce_store: signature.NonceStore | None = None) -> types.SimpleNamespace:
    return types.SimpleNamespace(state=types.SimpleNamespace(nonce_store=nonce_store or signature.NonceStore()))


def _signed_request(
    key: bytes,
    app: types.SimpleNamespace | None = None,
    path: str = "/pf/t/root/whoami",
    body: bytes = b"{}",
) -> tuple[starlette.requests.Request, str]:
    prepared = requests.PreparedRequest()
    prepared.method = "GET"
    prepared.url = f"http://testserver{path}"
    prepared.headers = requests.structures.CaseInsensitiveDict()
    prepared.body = body

    hmac_signer = client_signer.HmacSigner("session", key)
    http_signatures.Auth([hmac_signer])(prepared)

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
    key_id = f"session:{hmac_signer.thumbprint()}"
    return request, key_id


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
    request1, key_id1 = _signed_request(key1, app=app)
    request2, key_id2 = _signed_request(key2, app=app)
    assert key_id1 != key_id2

    signature.verify(request1, key_id=key_id1, key=jwk.Symmetric.from_bytes(key1))
    signature.verify(request2, key_id=key_id2, key=jwk.Symmetric.from_bytes(key2))


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
