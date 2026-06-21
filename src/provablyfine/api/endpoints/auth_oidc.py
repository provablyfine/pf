import base64
import json
import time

import cryptography.exceptions
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.utils
import cryptography.hazmat.primitives.hashes
import fastapi
import fastapi.requests
import fastapi.responses
import requests

from .. import converters, crypto_policy, model, responses, schemas, signature
from ..context import ctx

router = fastapi.APIRouter()

_204 = fastapi.responses.Response(status_code=204)


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _verify_oidc_token(issuer: str, client_id: str, id_token: str) -> str:
    """Verify an OIDC id_token JWT and return the email claim."""
    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    header_b64, payload_b64, signature_b64 = parts

    header = json.loads(_b64url_decode(header_b64))
    kid = header.get("kid")
    alg = header.get("alg")

    if alg not in ("RS256", "ES256"):
        raise ValueError(f"Unsupported JWT algorithm: {alg}")

    # Fetch OIDC discovery document
    discovery_resp = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=10)
    discovery_resp.raise_for_status()
    discovery = discovery_resp.json()
    jwks_uri = discovery["jwks_uri"]

    # Fetch JWKS
    jwks_resp = requests.get(jwks_uri, timeout=10)
    jwks_resp.raise_for_status()
    jwks = jwks_resp.json()

    # Find matching JWK by kid
    jwk_dict = None
    for k in jwks.get("keys", []):
        if kid is None or k.get("kid") == kid:
            jwk_dict = k
            break
    if jwk_dict is None:
        raise ValueError(f"No matching JWK found for kid={kid}")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature_bytes = _b64url_decode(signature_b64)

    if alg == "RS256":
        n = int.from_bytes(_b64url_decode(jwk_dict["n"]), "big")
        e = int.from_bytes(_b64url_decode(jwk_dict["e"]), "big")
        public_key = cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers(e, n).public_key()
        public_key.verify(
            signature_bytes,
            signing_input,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cryptography.hazmat.primitives.hashes.SHA256(),
        )
    else:  # ES256
        x = int.from_bytes(_b64url_decode(jwk_dict["x"]), "big")
        y = int.from_bytes(_b64url_decode(jwk_dict["y"]), "big")
        public_key = cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers(
            x, y, cryptography.hazmat.primitives.asymmetric.ec.SECP256R1()
        ).public_key()
        r = int.from_bytes(signature_bytes[:32], "big")
        s = int.from_bytes(signature_bytes[32:], "big")
        der_sig = cryptography.hazmat.primitives.asymmetric.utils.encode_dss_signature(r, s)
        public_key.verify(
            der_sig,
            signing_input,
            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256()),
        )

    # Validate claims
    payload = json.loads(_b64url_decode(payload_b64))
    now = int(time.time())

    if payload.get("iss") != issuer:
        raise ValueError(f"JWT issuer mismatch: {payload.get('iss')} != {issuer}")

    aud = payload.get("aud")
    if isinstance(aud, list):
        if client_id not in aud:
            raise ValueError("JWT audience mismatch")
    elif aud != client_id:
        raise ValueError(f"JWT audience mismatch: {aud} != {client_id}")

    if payload.get("exp", 0) <= now:
        raise ValueError("JWT is expired")

    email = payload.get("email")
    if not email:
        raise ValueError("JWT missing email claim")

    return email


@router.post(
    "/auth/oidc/login",
    status_code=204,
    responses={400: responses.PROBLEM, 403: responses.PROBLEM},
)
def oidc_login_endpoint(
    request: fastapi.requests.Request, data: schemas.auth.OidcLoginRequest
) -> fastapi.responses.Response:
    session_key = converters.public_from_schema(data.session_public_key)
    crypto_policy.enforce_key_is_allowed(session_key)
    model.denylist.enforce_not_denied(session_key.thumbprint())

    # Verify proof-of-possession: request must be signed with the claimed session key
    signature.verify(request, f"session:{session_key.thumbprint()}", session_key)

    # Look up auth config
    ac = model.auth_config.read_one(name=data.auth_name)
    if ac is None or not ac.is_enabled:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Auth config not found or disabled")
        )
    if ac.type not in ("oidc", "oidc-device-code"):
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="Auth config is not of type oidc or oidc-device-code")
        )

    # Verify OIDC token
    try:
        email = _verify_oidc_token(
            issuer=ac.config["issuer"],
            client_id=ac.config["client_id"],
            id_token=data.id_token,
        )
    except (ValueError, cryptography.exceptions.InvalidSignature, Exception) as exc:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="OIDC token verification failed", detail=str(exc))
        )

    # Look up identity by email
    identity = model.identity.read_one(name=email)
    if identity is None:
        raise responses.ProblemHTTPException(
            responses.problem_response(status_code=403, title="No identity for this account")
        )

    # Tag restriction: if auth config has tag_id_list, identity must share at least one (OR semantics)
    if ac.tag_id_list:
        if not any(tag_id in identity.tag_id_list for tag_id in ac.tag_id_list):
            raise responses.ProblemHTTPException(
                responses.problem_response(status_code=403, title="Identity does not have a required tag")
            )

    # Create session key record
    now = int(time.time())
    ctx.app_db.identity_session_key.create(
        id=session_key.thumbprint(),
        public_key=session_key.to_dict(),
        identity_id=identity.id,
        created_at=now,
        is_revoked=False,
        revoked_at=None,
        expires_at=now + ctx.config.session_duration_s,
        login_ip=request.client.host if request.client else None,
    )
    return _204
