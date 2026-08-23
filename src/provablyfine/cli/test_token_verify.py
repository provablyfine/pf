import time

import jwt
import pytest

from .. import jwk
from . import token_verify

_ISSUER = "https://issuer.example/pf/t/root/public/oidc"
_AUDIENCE = "host-1"


def _new_key_pair() -> tuple[jwk.Private, jwt.PyJWK]:
    private = jwk.Private.generate_ed25519()
    public_jwk = jwt.PyJWK(private.public().to_dict(), algorithm="EdDSA")
    return private, public_jwk


def _sign(private: jwk.Private, claims: dict[str, object], kid: str = "kid1") -> str:
    return jwt.encode(claims, private.to_crypto(), algorithm="EdDSA", headers={"kid": kid})


def _base_claims(now: int, **overrides: object) -> dict[str, object]:
    claims: dict[str, object] = {
        "sub": "42",
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "iat": now,
        "exp": now + 60,
        "jti": "jti-1",
        "name": "alice",
        "tenant_id": 1,
        "use": "connect",
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def verifier(monkeypatch: pytest.MonkeyPatch) -> tuple[token_verify.SingleIssuerVerifier, jwk.Private]:
    private, public_jwk = _new_key_pair()
    v = token_verify.SingleIssuerVerifier(_ISSUER)
    monkeypatch.setattr(v._jwk_client, "get_signing_key", lambda kid: public_jwk)
    return v, private


def test_verify_accepts_valid_token(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    token = _sign(private, _base_claims(now, deadline=now + 3600, cid="3fa85f64-5717-4562-b3fc-2c963f66afa6"))

    result = v.verify(token, _AUDIENCE, now, "connect")

    assert result is not None
    assert result.sub == "42"
    assert result.name == "alice"
    assert result.jti == "jti-1"
    assert result.deadline == now + 3600
    assert result.cid == "3fa85f64-5717-4562-b3fc-2c963f66afa6"


def test_verify_omits_absent_optional_claims(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    token = _sign(private, _base_claims(now))

    result = v.verify(token, _AUDIENCE, now, "connect")

    assert result is not None
    assert result.deadline is None
    assert result.cid is None


def test_verify_rejects_bad_signature(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, _ = verifier
    now = int(time.time())
    wrong_private, _ = _new_key_pair()
    token = _sign(wrong_private, _base_claims(now))

    assert v.verify(token, _AUDIENCE, now, "connect") is None


def test_verify_rejects_wrong_issuer(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    token = _sign(private, _base_claims(now, iss="https://someone-else.example/pf/t/other/public/oidc"))

    assert v.verify(token, _AUDIENCE, now, "connect") is None


def test_verify_rejects_wrong_audience(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    token = _sign(private, _base_claims(now))

    assert v.verify(token, "some-other-host", now, "connect") is None


def test_verify_rejects_missing_required_claim(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    claims = _base_claims(now)
    del claims["jti"]
    token = _sign(private, claims)

    assert v.verify(token, _AUDIENCE, now, "connect") is None


def test_verify_rejects_expired_token(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    token = _sign(private, _base_claims(now - 120, exp=now - 60))

    assert v.verify(token, _AUDIENCE, now, "connect") is None


def test_verify_rejects_replayed_jti(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    token = _sign(private, _base_claims(now))

    assert v.verify(token, _AUDIENCE, now, "connect") is not None
    assert v.verify(token, _AUDIENCE, now, "connect") is None


def test_verify_rejects_wrong_purpose(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    token = _sign(private, _base_claims(now, use="register"))

    assert v.verify(token, _AUDIENCE, now, "connect") is None


def test_verify_rejects_missing_use_claim(verifier: tuple[token_verify.SingleIssuerVerifier, jwk.Private]) -> None:
    v, private = verifier
    now = int(time.time())
    claims = _base_claims(now)
    del claims["use"]
    token = _sign(private, claims)

    assert v.verify(token, _AUDIENCE, now, "connect") is None
