from __future__ import annotations

import dataclasses
import logging

import jwt

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TrustedKey:
    issuer: str
    key: jwt.PyJWK


class TrustedKeys:
    def __init__(self, issuer_prefix: str):
        self._issuer_prefix = issuer_prefix
        self._client_by_iss: dict[str, jwt.PyJWKClient] = {}

    def lookup(self, token: str) -> TrustedKey | None:
        try:
            unverified = jwt.decode_complete(token, options={"verify_signature": False, "require": ["iss"]})
        except jwt.exceptions.InvalidTokenError as e:
            logger.debug(f"Invalid token: {e}")
            return None
        header = unverified["header"]
        payload = unverified["payload"]
        kid = header.get("kid")
        if kid is None:
            logger.debug("Missing kid in header")
            return None
        iss = payload["iss"]

        if not iss.startswith(self._issuer_prefix):
            logger.debug(f"Invalid token: issuer does not match our prefix: {iss}!={self._issuer_prefix}")
            return None

        client = self._client_by_iss.get(iss)
        if client is None:
            client = jwt.PyJWKClient(f"{iss}/.well-known/jwks.json")
            self._client_by_iss[iss] = client
        try:
            key = client.get_signing_key(kid)
        except jwt.exceptions.PyJWKClientError:
            logger.warning(
                f"Invalid key iss={iss} kid={kid}. "
                "Something is wrong with your key rotation or someone is trying to screw you."
            )
            return None

        return TrustedKey(issuer=iss, key=key)
