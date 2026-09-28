from __future__ import annotations

import base64
import http.server
import json
import pathlib
import threading
import time
import typing
import uuid

import jwt
import pytest
import sqlalchemy

from .. import jwk
from . import db, jwt_validator, migrate, registry_db


class _JwksHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = typing.cast("_JwksServer", self.server)
        with server.lock:
            server.get_count += 1
            server.get_paths.append(self.path)
            body = json.dumps(server.keys_response).encode()
            delay = server.delay_s
        time.sleep(delay)
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class _JwksServer(http.server.HTTPServer):
    """A real, tiny JWKS server: avoids mocking jwt.PyJWKClient's network calls."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _JwksHandler)
        self.lock = threading.Lock()
        self.get_count = 0
        self.get_paths: list[str] = []
        self.keys_response: dict[str, object] = {"keys": []}
        self.delay_s = 0.0
        self.base_url = f"http://127.0.0.1:{self.server_port}"
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def set_keys(self, keys: list[dict[str, str]]) -> None:
        with self.lock:
            self.keys_response = {"keys": keys}

    def stop(self) -> None:
        self.shutdown()
        self._thread.join(timeout=5)


@pytest.fixture
def jwks_server() -> typing.Iterator[_JwksServer]:
    server = _JwksServer()
    yield server
    server.stop()


@pytest.fixture
def registry_engine(tmp_path: pathlib.Path) -> typing.Iterator[sqlalchemy.Engine]:
    url = f"sqlite:///{tmp_path / 'registry.db'}"
    migrate.create_registry(url)
    engine = db.create_engine(url)
    yield engine
    engine.dispose()


class _FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


def _add_tenant(engine: sqlalchemy.Engine, tenant_uuid: str, is_enabled: bool = True) -> None:
    with db.begin(engine, write=True) as conn:
        registry_db.create(conn).tenant.create(
            uuid=tenant_uuid,
            name=tenant_uuid,
            display_name=tenant_uuid,
            owner_id=None,
            database_url="sqlite://",
            is_enabled=is_enabled,
            is_initialized=True,
            is_deleted=False,
            created_at=0,
        )


def _jwk_entry(private: jwk.Private) -> dict[str, str]:
    return {**private.public().to_dict(), "kid": private.thumbprint(), "alg": "EdDSA", "use": "sig"}


def _issuer(base_url: str, tenant_uuid: str) -> str:
    return f"{base_url}/pf/t/{tenant_uuid}/public/oidc"


def _raw_token(payload: dict[str, object], private: jwk.Private, kid: str) -> str:
    """Build a JWT by hand, bypassing jwt.encode's own claim validation (e.g. that iss is a str)."""

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}".encode()
    signature = private.to_crypto().sign(signing_input)
    return f"{signing_input.decode()}.{b64url(signature)}"


def _token(private: jwk.Private, iss: object, kid: str | None = None) -> str:
    claims: dict[str, object] = {
        "sub": "1",
        "iss": iss,
        "aud": "host",
        "iat": 0,
        "exp": 9999999999,
        "jti": "1",
        "name": "alice",
        "use": "connect",
    }
    header = {"kid": kid if kid is not None else private.thumbprint()}
    return jwt.encode(claims, private.to_crypto(), algorithm="EdDSA", headers=header)


def test_lookup_accepts_valid_token(jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine) -> None:
    tenant_uuid = str(uuid.uuid4())
    _add_tenant(registry_engine, tenant_uuid)
    private = jwk.Private.generate_ed25519()
    jwks_server.set_keys([_jwk_entry(private)])
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine)
    iss = _issuer(jwks_server.base_url, tenant_uuid)

    result = trusted.lookup(_token(private, iss))

    assert result is not None
    assert result.issuer == iss
    assert jwks_server.get_count == 1


@pytest.mark.parametrize(
    "shape",
    [
        "{base}/pf/t/{uuid}",  # missing /public/oidc suffix
        "{base}/pf/t/{uuid}/public/oidc/extra",  # trailing segment
        "{base}/pf/t/{uuid}//public/oidc",  # embedded slash in the uuid segment
        "{base}/wrong/t/{uuid}/public/oidc",  # wrong prefix entirely
    ],
)
def test_lookup_rejects_malformed_issuer_shape(
    jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine, shape: str
) -> None:
    tenant_uuid = str(uuid.uuid4())
    _add_tenant(registry_engine, tenant_uuid)
    private = jwk.Private.generate_ed25519()
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine)
    iss = shape.format(base=jwks_server.base_url, uuid=tenant_uuid)

    assert trusted.lookup(_token(private, iss)) is None
    assert jwks_server.get_count == 0


def test_lookup_rejects_non_canonical_uuid(jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine) -> None:
    """MySQL/MariaDB's default collation on tenant.uuid is case-insensitive.

    Without requiring the exact canonical form, an uppercase variant of a real tenant's UUID
    would still pass the existence check on those backends, getting its own cache slot and its
    own forced-refresh budget on top of the real one. Rejecting non-canonical form up front,
    before any database access, closes this on every backend.
    """
    tenant_uuid = str(uuid.uuid4())
    _add_tenant(registry_engine, tenant_uuid)
    private = jwk.Private.generate_ed25519()
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine)
    iss = _issuer(jwks_server.base_url, tenant_uuid.upper())

    assert trusted.lookup(_token(private, iss)) is None
    assert jwks_server.get_count == 0


def test_lookup_rejects_unknown_tenant(jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine) -> None:
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine)
    private = jwk.Private.generate_ed25519()
    iss = _issuer(jwks_server.base_url, str(uuid.uuid4()))

    assert trusted.lookup(_token(private, iss)) is None
    assert jwks_server.get_count == 0


def test_lookup_rejects_disabled_tenant(jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine) -> None:
    tenant_uuid = str(uuid.uuid4())
    _add_tenant(registry_engine, tenant_uuid, is_enabled=False)
    private = jwk.Private.generate_ed25519()
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine)
    iss = _issuer(jwks_server.base_url, tenant_uuid)

    assert trusted.lookup(_token(private, iss)) is None
    assert jwks_server.get_count == 0


def test_lookup_rejects_non_string_issuer(jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine) -> None:
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine)
    private = jwk.Private.generate_ed25519()
    token = _raw_token({"iss": 12345, "sub": "1"}, private, kid=private.thumbprint())

    assert trusted.lookup(token) is None


def test_lookup_handles_empty_jwks_without_raising(
    jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine
) -> None:
    """A real, enabled tenant with no OIDC keys yet is a legitimate state, not an error."""
    tenant_uuid = str(uuid.uuid4())
    _add_tenant(registry_engine, tenant_uuid)
    private = jwk.Private.generate_ed25519()
    jwks_server.set_keys([])
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine)
    iss = _issuer(jwks_server.base_url, tenant_uuid)

    assert trusted.lookup(_token(private, iss)) is None


def test_lookup_bounds_cache_size(jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine) -> None:
    tenant_uuids = [str(uuid.uuid4()) for _ in range(5)]
    for tenant_uuid in tenant_uuids:
        _add_tenant(registry_engine, tenant_uuid)
    private = jwk.Private.generate_ed25519()
    jwks_server.set_keys([_jwk_entry(private)])
    trusted = jwt_validator.TrustedKeys(f"{jwks_server.base_url}/pf/t", registry_engine, max_cached_issuers=3)

    for tenant_uuid in tenant_uuids:
        iss = _issuer(jwks_server.base_url, tenant_uuid)
        assert trusted.lookup(_token(private, iss)) is not None

    assert len(trusted._client_by_iss) == 3  # the cache bound is the thing under test
    assert jwks_server.get_count == 5

    # The earliest-inserted issuer was evicted: looking it up again is a fresh cache miss.
    first_iss = _issuer(jwks_server.base_url, tenant_uuids[0])
    assert trusted.lookup(_token(private, first_iss)) is not None
    assert jwks_server.get_count == 6


def test_lookup_rate_limits_forced_refresh(jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine) -> None:
    tenant_uuid = str(uuid.uuid4())
    _add_tenant(registry_engine, tenant_uuid)
    private = jwk.Private.generate_ed25519()
    jwks_server.set_keys([_jwk_entry(private)])
    clock = _FakeClock()
    trusted = jwt_validator.TrustedKeys(
        f"{jwks_server.base_url}/pf/t", registry_engine, min_forced_refresh_interval=30.0, clock=clock
    )
    iss = _issuer(jwks_server.base_url, tenant_uuid)

    # Priming lookup creates the cache entry and does one unforced fetch.
    assert trusted.lookup(_token(private, iss)) is not None
    assert jwks_server.get_count == 1

    # Right after creation the floor blocks a forced refresh even for an unknown kid: the
    # entry was just filled, so refetching immediately again would gain nothing.
    assert trusted.lookup(_token(private, iss, kid="unknown-1")) is None
    assert jwks_server.get_count == 1
    assert trusted.lookup(_token(private, iss, kid="unknown-2")) is None
    assert jwks_server.get_count == 1

    clock.advance(31.0)

    # Floor elapsed: exactly one forced refresh is allowed through.
    assert trusted.lookup(_token(private, iss, kid="unknown-3")) is None
    assert jwks_server.get_count == 2

    # Immediately after that forced refresh, the floor blocks again.
    assert trusted.lookup(_token(private, iss, kid="unknown-4")) is None
    assert jwks_server.get_count == 2


def test_lookup_forced_refresh_race_allows_only_one_network_call(
    jwks_server: _JwksServer, registry_engine: sqlalchemy.Engine
) -> None:
    """The forced-refresh floor must hold even when many requests race past it at once.

    The timestamp is stamped before the network call, inside the lock, so only the thread
    that wins the compare-and-set does I/O; every other concurrent caller must see the
    updated timestamp and return immediately with none.
    """
    tenant_uuid = str(uuid.uuid4())
    _add_tenant(registry_engine, tenant_uuid)
    private = jwk.Private.generate_ed25519()
    jwks_server.set_keys([_jwk_entry(private)])
    clock = _FakeClock()
    trusted = jwt_validator.TrustedKeys(
        f"{jwks_server.base_url}/pf/t", registry_engine, min_forced_refresh_interval=30.0, clock=clock
    )
    iss = _issuer(jwks_server.base_url, tenant_uuid)

    assert trusted.lookup(_token(private, iss)) is not None
    assert jwks_server.get_count == 1
    clock.advance(31.0)

    jwks_server.delay_s = 0.2
    thread_count = 8
    barrier = threading.Barrier(thread_count)
    results: list[jwt_validator.TrustedKey | None] = [None] * thread_count

    def worker(i: int) -> None:
        barrier.wait()
        results[i] = trusted.lookup(_token(private, iss, kid="unknown-race"))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(thread_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(result is None for result in results)
    assert jwks_server.get_count == 2
