import dataclasses
import logging

import jwt

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class VerifiedToken:
    sub: str
    name: str
    jti: str
    deadline: int | None
    cid: str | None


class SingleIssuerVerifier:
    """Verifies pf bastion tokens against exactly one already-known issuer.

    Unlike api.jwt_validator.TrustedKeys (arbitrary-issuer discovery by
    prefix, appropriate for pf-api serving many tenants), a `pf bastion
    register` process only ever needs to trust the single tenant it is
    itself logged into. That issuer is resolved once from the CLI's own
    directory/login config, never from the token's own `iss` claim.
    """

    def __init__(self, issuer: str) -> None:
        self._issuer = issuer
        self._jwk_client = jwt.PyJWKClient(f"{issuer}/.well-known/jwks.json")
        self._seen_jti: dict[str, int] = {}

    def _sweep_expired(self, now: int) -> None:
        expired = [j for j, exp in self._seen_jti.items() if exp <= now]
        for j in expired:
            del self._seen_jti[j]

    def verify(self, token: str, expected_audience: str, now: int) -> VerifiedToken | None:
        try:
            unverified = jwt.decode_complete(token, options={"verify_signature": False, "require": ["iss"]})
        except jwt.exceptions.InvalidTokenError as e:
            logger.debug(f"token: unparseable: {e}")
            return None
        kid = unverified["header"].get("kid")
        if kid is None:
            logger.debug("token: missing kid in header")
            return None
        try:
            key = self._jwk_client.get_signing_key(kid)
        except jwt.exceptions.PyJWKClientError:
            logger.debug(f"token: unknown kid={kid}")
            return None

        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                issuer=self._issuer,
                audience=expected_audience,
                options={"require": ["sub", "name", "jti", "exp"]},
            )
        except jwt.exceptions.InvalidTokenError as e:
            logger.debug(f"token: rejected: {e}")
            return None

        jti = payload["jti"]
        self._sweep_expired(now)
        if jti in self._seen_jti:
            logger.warning("token: jti already used, rejecting (replay)")
            return None
        self._seen_jti[jti] = payload["exp"]

        return VerifiedToken(
            sub=payload["sub"],
            name=payload["name"],
            jti=jti,
            deadline=payload.get("deadline"),
            cid=payload.get("cid"),
        )
