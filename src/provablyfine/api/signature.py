import hashlib
import hmac
import time
import typing

import cryptography.exceptions
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.ed25519
import cryptography.hazmat.primitives.hashes
import fastapi.requests
import http_sfv

from .. import jwk
from . import crypto_policy, model, responses
from .context import ctx

# http_sfv type stubs are incomplete
# pyright: reportPrivateImportUsage=false, reportUnknownMemberType=false, reportUnknownVariableType=false

# Signatures older than this are rejected, regardless of nonce tracking.
FRESHNESS_WINDOW_SECONDS = 300


class NonceStore:
    """In-memory TTL set of (key_id, nonce) pairs used to reject replayed signatures."""

    def __init__(self, window_seconds: int = FRESHNESS_WINDOW_SECONDS):
        self._window_seconds = window_seconds
        self._seen: dict[tuple[str, str], int] = {}

    def check_and_add(self, key_id: str, nonce: str, now: int) -> bool:
        """Records (key_id, nonce) as seen; returns False if it was already seen."""
        self._expire(now)
        entry = (key_id, nonce)
        if entry in self._seen:
            return False
        self._seen[entry] = now
        return True

    def _expire(self, now: int) -> None:
        expired = [entry for entry, seen_at in self._seen.items() if now - seen_at > self._window_seconds]
        for entry in expired:
            del self._seen[entry]


def _parse_signature_input(signature_input: str) -> dict[str, tuple[str, http_sfv.InnerList]]:
    d = http_sfv.Dictionary()
    try:
        d.parse(signature_input.encode())
    except Exception as e:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Invalid Signature-Input header", detail=str(e))
        )
    keyid_by_label: dict[str, tuple[str, http_sfv.InnerList]] = {}
    for label, v in d.items():
        if not isinstance(v, http_sfv.InnerList):
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=400, title="Invalid Signature-Input", detail=f"Expected inner list for {label}"
                )
            )
        inner: http_sfv.InnerList = v
        if "keyid" not in inner.params:
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=400, title="Invalid Signature-Input", detail=f"Missing keyid in {label}"
                )
            )
        keyid = inner.params["keyid"]
        if not isinstance(keyid, str):
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=400, title="Invalid Signature-Input", detail=f"keyid mistyped in {label}"
                )
            )
        keyid_by_label[label] = (keyid, inner)
    return keyid_by_label


def _parse_signature(signature: str) -> dict[str, bytes]:
    d = http_sfv.Dictionary()
    try:
        d.parse(signature.encode())
    except Exception as e:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Invalid Signature header", detail=str(e))
        )
    for label, v in d.items():
        if not isinstance(v, http_sfv.Item):
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=400, title="Invalid Signature header", detail=f"Expected item for {label}"
                )
            )
    return {label: v.value for label, v in d.items()}


def _build_signature_base(
    request: fastapi.requests.Request,
    inner: http_sfv.InnerList,
    sig_params: str,
) -> bytes:
    """Build the signature base string per RFC 9421 §2.5."""
    parts: list[str] = []
    for item in inner:
        c: str = item.value
        match c:
            case "@method":
                parts.append(f'"@method": {request.method}')
            case "@authority":
                parts.append(f'"@authority": {request.url.netloc}')
            case "@target-uri":
                parts.append(f'"@target-uri": {request.url}')
            case "@signature-params":
                parts.append(f'"@signature-params": {sig_params}')
            case _:
                parts.append(f'"{c}": {request.headers[c]}')
    return "\n".join(parts).encode()


def verify(request: fastapi.requests.Request, key_id: str, key: jwk.Symmetric | jwk.Public) -> None:
    content_digest = str(http_sfv.Dictionary({"sha-256": hashlib.sha256(request.state.body).digest()}))
    if request.headers["Content-Digest"] != content_digest:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Content hash does not match Content-Digest header")
        )

    if "Signature" not in request.headers:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Missing Signature header")
        )
    if "Signature-Input" not in request.headers:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Missing Signature-Input header")
        )

    keyid_by_label = _parse_signature_input(request.headers["Signature-Input"])
    signature_by_label = _parse_signature(request.headers["Signature"])

    label_by_keyid = {keyid: (label, inner) for label, (keyid, inner) in keyid_by_label.items()}
    if key_id not in label_by_keyid:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Unable to find keyid in Signature-Input", detail=key_id)
        )
    label, inner = label_by_keyid[key_id]

    if "nonce" not in inner.params:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Missing nonce in Signature-Input", detail=key_id)
        )
    nonce = inner.params["nonce"]
    if not isinstance(nonce, str):
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="nonce mistyped in Signature-Input", detail=key_id)
        )
    if "created" not in inner.params:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Missing created in Signature-Input", detail=key_id)
        )
    created: int = inner.params["created"]
    now = int(time.time())
    if now - created > FRESHNESS_WINDOW_SECONDS:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Signature is too old", detail=key_id)
        )

    nonce_store: NonceStore = request.app.state.nonce_store
    if not nonce_store.check_and_add(key_id, nonce, now):
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Signature nonce has already been used", detail=key_id)
        )

    if label not in signature_by_label:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Unable to find label in Signature", detail=label)
        )

    sig_params = str(inner)
    sig_base = _build_signature_base(request, inner, sig_params)
    sig_bytes = signature_by_label[label]

    try:
        match key.type:
            case jwk.KeyType.SYMMETRIC:
                sym_key = typing.cast(jwk.Symmetric, key)
                expected = hmac.new(sym_key.to_bytes(), sig_base, hashlib.sha256).digest()
                if not hmac.compare_digest(expected, sig_bytes):
                    raise cryptography.exceptions.InvalidSignature()
            case jwk.KeyType.ED25519:
                pub_key = typing.cast(jwk.Public, key)
                pub = pub_key.to_crypto()
                assert isinstance(pub, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey)
                pub.verify(sig_bytes, sig_base)
            case jwk.KeyType.ECDSA_NISTP256:
                pub_key = typing.cast(jwk.Public, key)
                pub = pub_key.to_crypto()
                assert isinstance(pub, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey)
                pub.verify(
                    sig_bytes,
                    sig_base,
                    cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256()),
                )
            case _:
                raise responses.ProblemHTTPException(
                    responses.problem_response(status_code=400, title="Unsupported key type", detail=key_id)
                )
    except cryptography.exceptions.InvalidSignature:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Invalid signature", detail=key_id)
        )

    covered = {item.value for item in inner}
    expected_covered = {"@authority", "@method", "@target-uri", "@signature-params", "content-digest"}
    if covered != expected_covered:
        raise responses.ProblemHTTPException(
            responses.problem_response(
                status_code=400,
                title="Signature does not cover the expected fields",
                detail=f"Got: {covered}. Expected: {expected_covered}",
            )
        )


def _get_keyid(request: fastapi.requests.Request, prefix: str) -> str:
    if "Signature-Input" not in request.headers:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=401, title="Missing Signature-Input header")
        )
    keyid_by_label = _parse_signature_input(request.headers["Signature-Input"])
    for _label, (keyid, _signature_input) in keyid_by_label.items():
        if not keyid.startswith(f"{prefix}:"):
            continue
        return keyid[len(f"{prefix}:") :]
    raise responses.ProblemHTTPException(
        responses.problem_response(status_code=401, title="Missing signature for prefix", detail=prefix)
    )


async def verify_invitation(
    request: fastapi.requests.Request,
) -> typing.AsyncGenerator[model.identity_invitation_key.IdentityInvitationKey, None]:
    key_id = _get_keyid(request, "invitation")
    invitation = model.identity_invitation_key.read(key_id)
    if invitation is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=401, title="Invitation does not exist")
        )
    if invitation.is_revoked:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=401, title="Invitation is revoked"))
    now = int(time.time())
    if invitation.expires_at <= now:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=401, title="Invitation is expired"))
    assert invitation.key.thumbprint() == key_id
    verify(request, key_id=f"invitation:{key_id}", key=invitation.key)
    with ctx.set_identity_id(invitation.identity_id):
        yield invitation


async def verify_account(request: fastapi.requests.Request) -> typing.AsyncGenerator[None, None]:
    key_id = _get_keyid(request, "account")
    account_key = ctx.app_db.identity_account_key.read_one(id=key_id)
    if account_key is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=401, title="Account does not exist")
        )
    if account_key.is_revoked:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=401, title="Account key is revoked")
        )
    key = jwk.Public.from_dict(account_key.public_key)
    crypto_policy.enforce_key_is_allowed(key)
    assert key.thumbprint() == key_id
    model.denylist.enforce_not_denied(key.thumbprint())
    verify(request, key_id=f"account:{key_id}", key=key)
    with ctx.set_identity_id(account_key.identity_id):
        yield


async def verify_session(request: fastapi.requests.Request) -> typing.AsyncGenerator[None, None]:
    key_id = _get_keyid(request, "session")
    session_key = ctx.app_db.identity_session_key.read_one(id=key_id)
    if session_key is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=401, title="Session does not exist")
        )
    if session_key.is_revoked:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=401, title="Session key is revoked")
        )
    now = int(time.time())
    if session_key.expires_at <= now:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=401, title="Session key is expired")
        )
    key = jwk.Public.from_dict(session_key.public_key)
    crypto_policy.enforce_key_is_allowed(key)
    assert key.thumbprint() == key_id
    model.denylist.enforce_not_denied(key.thumbprint())
    verify(request, key_id=f"session:{key_id}", key=key)
    with ctx.set_identity_id(session_key.identity_id):
        with ctx.set_active_role_id(session_key.role_id):
            with ctx.set_session_key_id(key_id):
                yield
