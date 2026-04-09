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
        if "keyid" not in v.params:
            raise responses.ProblemHTTPException(
                responses.problem_response(
                    status_code=400, title="Invalid Signature-Input", detail=f"Missing keyid in {label}"
                )
            )
        keyid_by_label[label] = (str(v.params["keyid"]), v)  # type: ignore[arg-type]
    return keyid_by_label


def _parse_signature(signature: str) -> dict[str, bytes]:
    d = http_sfv.Dictionary()
    try:
        d.parse(signature.encode())
    except Exception as e:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Invalid Signature header", detail=str(e))
        )
    return {label: v.value for label, v in d.items()}  # type: ignore[arg-type]


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
    if "created" not in inner.params:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Missing created in Signature-Input", detail=key_id)
        )
    created: int = inner.params["created"]
    if int(time.time()) - created > 5 * 3600:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=400, title="Signature is too old", detail=key_id)
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
            responses.problem_response(status_code=403, title="Missing Signature-Input header")
        )
    keyid_by_label = _parse_signature_input(request.headers["Signature-Input"])
    for _label, (keyid, _signature_input) in keyid_by_label.items():
        if not keyid.startswith(f"{prefix}:"):
            continue
        return keyid[len(f"{prefix}:") :]
    raise responses.ProblemHTTPException(
        responses.problem_response(status_code=403, title="Missing signature for prefix", detail=prefix)
    )


async def verify_invitation(request: fastapi.requests.Request) -> typing.AsyncGenerator[None, None]:
    key_id = _get_keyid(request, "invitation")
    invitation = model.identity_invitation_key.read(key_id)
    if invitation is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Invitation does not exist")
        )
    if invitation.is_revoked:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Invitation is revoked"))
    now = int(time.time())
    if invitation.expires_at <= now:
        raise responses.ProblemHTTPException(responses.problem_response(status_code=403, title="Invitation is expired"))
    assert invitation.key.thumbprint() == key_id
    verify(request, key_id=f"invitation:{key_id}", key=invitation.key)
    with ctx.set_invitation(invitation):
        with ctx.set_identity_id(invitation.identity_id):
            yield


async def verify_account(request: fastapi.requests.Request) -> typing.AsyncGenerator[None, None]:
    key_id = _get_keyid(request, "account")
    account_key = ctx.db.identity_account_key.read_one(id=key_id)
    if account_key is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Account does not exist")
        )
    if account_key.is_revoked:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Account key is revoked")
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
    session_key = ctx.db.identity_session_key.read_one(id=key_id)
    if session_key is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Session does not exist")
        )
    if session_key.is_revoked:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Session key is revoked")
        )
    now = int(time.time())
    if session_key.expires_at <= now:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Session key is expired")
        )
    key = jwk.Public.from_dict(session_key.public_key)
    crypto_policy.enforce_key_is_allowed(key)
    assert key.thumbprint() == key_id
    model.denylist.enforce_not_denied(key.thumbprint())
    verify(request, key_id=f"session:{key_id}", key=key)
    with ctx.set_identity_id(session_key.identity_id):
        yield
