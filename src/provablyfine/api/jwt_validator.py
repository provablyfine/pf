from __future__ import annotations

import collections.abc
import dataclasses
import logging
import threading
import time
import uuid

import jwt
import sqlalchemy

from . import db, registry_db

logger = logging.getLogger(__name__)

_ISSUER_SUFFIX = "/public/oidc"


@dataclasses.dataclass
class TrustedKey:
    issuer: str
    key: jwt.PyJWK


@dataclasses.dataclass
class _CachedClient:
    client: jwt.PyJWKClient
    last_forced_refresh: float


class TrustedKeys:
    def __init__(
        self,
        issuer_prefix: str,
        registry_engine: sqlalchemy.Engine,
        max_cached_issuers: int = 10_000,
        min_forced_refresh_interval: float = 30.0,
        clock: collections.abc.Callable[[], float] = time.monotonic,
    ):
        self._issuer_prefix = issuer_prefix
        self._registry_engine = registry_engine
        self._max_cached_issuers = max_cached_issuers
        self._min_forced_refresh_interval = min_forced_refresh_interval
        self._clock = clock
        self._client_by_iss: dict[str, _CachedClient] = {}
        self._lock = threading.Lock()

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
        if not isinstance(iss, str):
            logger.debug("Invalid token: issuer is not a string")
            return None

        tenant_uuid = self._extract_tenant_uuid(iss)
        if tenant_uuid is None:
            logger.debug(f"Invalid token: issuer does not match the expected shape: {iss}")
            return None

        entry = self._client_by_iss.get(iss)
        if entry is None:
            if not self._tenant_exists(tenant_uuid):
                logger.debug(f"Invalid token: no enabled tenant {tenant_uuid}")
                return None
            entry = self._get_or_create_entry(iss)

        signing_keys = self._safe_signing_keys(entry.client, refresh=False)
        key = jwt.PyJWKClient.match_kid(signing_keys, kid)

        if key is None and self._allow_forced_refresh(entry):
            signing_keys = self._safe_signing_keys(entry.client, refresh=True)
            key = jwt.PyJWKClient.match_kid(signing_keys, kid)

        if key is None:
            logger.warning(
                f"Invalid key iss={iss} kid={kid}. "
                "Something is wrong with your key rotation or someone is trying to screw you."
            )
            return None

        return TrustedKey(issuer=iss, key=key)

    def _extract_tenant_uuid(self, iss: str) -> str | None:
        prefix = self._issuer_prefix + "/"
        if not iss.startswith(prefix) or not iss.endswith(_ISSUER_SUFFIX):
            return None
        candidate = iss[len(prefix) : -len(_ISSUER_SUFFIX)]
        if not candidate or "/" in candidate:
            return None
        try:
            canonical = str(uuid.UUID(candidate))
        except ValueError:
            return None
        if candidate != canonical:
            return None
        return candidate

    def _tenant_exists(self, tenant_uuid: str) -> bool:
        # The tenant is only checked once, at cache-miss time, not on every call: re-checking
        # every request would add a database round trip to the hot path. A tenant disabled or
        # deleted after its client was cached stays trusted for at most the JWK-set cache
        # lifespan (a few minutes).
        with db.begin(self._registry_engine) as conn:
            tenant_row = registry_db.create(conn).tenant.read_one(uuid=tenant_uuid)
        return tenant_row is not None and tenant_row.is_enabled

    def _get_or_create_entry(self, iss: str) -> _CachedClient:
        with self._lock:
            entry = self._client_by_iss.get(iss)
            if entry is None:
                entry = _CachedClient(
                    client=jwt.PyJWKClient(f"{iss}/.well-known/jwks.json"),
                    last_forced_refresh=self._clock(),
                )
                self._client_by_iss[iss] = entry
                if len(self._client_by_iss) > self._max_cached_issuers:
                    oldest = next(iter(self._client_by_iss))
                    self._client_by_iss.pop(oldest, None)
            return entry

    def _allow_forced_refresh(self, entry: _CachedClient) -> bool:
        # The timestamp is stamped before the network call is made, inside the lock, so the floor
        # holds under a race: only the thread that wins the compare-and-set does I/O, every other
        # concurrent caller observes the updated timestamp and returns immediately with none.
        with self._lock:
            now = self._clock()
            if now - entry.last_forced_refresh < self._min_forced_refresh_interval:
                return False
            entry.last_forced_refresh = now
            return True

    def _safe_signing_keys(self, client: jwt.PyJWKClient, refresh: bool) -> list[jwt.PyJWK]:
        try:
            return client.get_signing_keys(refresh=refresh)
        except (jwt.exceptions.PyJWKClientError, jwt.exceptions.PyJWKSetError) as e:
            logger.debug(f"Unable to fetch signing keys (refresh={refresh}): {e}")
            return []
