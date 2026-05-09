from __future__ import annotations

import dataclasses
import logging

import jwt
import pydantic

from .. import anet
from . import http, relay, trusted_key

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Config:
    domain_suffix: str
    dev_tenant_id: int | None
    dev_name: str | None
    issuer_prefix: str | None
    log_level: int = 0
    log_filename: str | None = None


@dataclasses.dataclass
class Token:
    name: str
    tenant_id: int


class AppSnapshot(pydantic.BaseModel):
    """Snapshot of full application relay state."""

    relays: list[relay.RelaySnapshot]


@dataclasses.dataclass
class AppState:
    trusted_keys: trusted_key.TrustedKeys | None
    audience: str
    dev_tenant_id: int | None
    dev_name: str | None
    relays: dict[tuple[int, str], relay.Relay]

    @classmethod
    def create(cls, conf: Config, relays: dict[tuple[int, str], relay.Relay]) -> AppState:
        state = AppState(
            trusted_keys=trusted_key.TrustedKeys(conf.issuer_prefix) if conf.issuer_prefix else None,
            audience="bastion",
            dev_tenant_id=conf.dev_tenant_id,
            dev_name=conf.dev_name,
            relays=relays,
        )
        return state

    def stop(self):
        for relay in self.relays.values():
            relay.stop()

    async def wait_stop(self):
        for relay in self.relays.values():
            await relay.wait_stop()

    def snapshot(self) -> AppSnapshot:
        relay_snapshots = [relay.snapshot() for relay in list(self.relays.values())]
        return AppSnapshot(relays=relay_snapshots)

    @classmethod
    def restore(cls, conf: Config, snap: AppSnapshot) -> AppState:
        relays = {r.client_key: relay.Relay.restore(r) for r in snap.relays}

        def _on_relay_done(client_key: tuple[int, str]) -> None:
            relays.pop(client_key, None)

        for r in relays.values():
            r.add_done_callback(_on_relay_done)
        return AppState.create(conf, relays)


def verify_token(state: AppState, request: anet.http.Request) -> Token | None:
    if state.dev_tenant_id is not None and state.dev_name is not None:
        return Token(tenant_id=state.dev_tenant_id, name=state.dev_name)
    assert state.trusted_keys is not None

    if "proxy-authorization" not in request.headers:
        logger.debug("Missing Proxy-Authorization header")
        return None
    authorization = request.headers["proxy-authorization"]
    space = authorization.find(" ")
    if space == -1:
        logger.debug("Invalid Proxy-Authorization header")
        return None
    if authorization[:space] != "Bearer":
        logger.debug("Proxy-Authorization header must contain a Bearer token")
        return None
    token = authorization[space + 1 :].strip(" ")

    trusted_key = state.trusted_keys.lookup(token)
    if trusted_key is None:
        logger.error("Could not find matching trusted key")
        return None

    try:
        payload = jwt.decode(
            token,
            trusted_key.key,
            algorithms=["EdDSA"],
            audience=state.audience,
            issuer=trusted_key.issuer,
            options={"require": ["sub", "name", "tenant_id"]},
        )
    except jwt.exceptions.InvalidTokenError as e:
        logger.debug(f"Invalid token: {e}")
        return None

    if not isinstance(payload["tenant_id"], int):
        logger.debug(f"Invalid token: tenant_id is not an integer: {payload['tenant_id']}")
        return None

    assert payload["tenant_id"] >= 1
    return Token(name=payload["name"], tenant_id=payload["tenant_id"])


async def register_handler(state: AppState, request: anet.http.Request, sock_name: str) -> anet.http.Response | None:
    token = verify_token(state, request)
    if token is None:
        return http.response(status_code=403)

    sock = anet.sockets.store.get(sock_name)
    assert sock is not None
    await http.response(status_code=200).serialize(sock)

    logger.info(f"Registering identity {token.tenant_id}/{token.name}")
    client_key = (token.tenant_id, token.name)
    r = relay.Relay.start(sock_name, client_key)
    state.relays[client_key] = r

    def _on_relay_done(client_key: tuple[int, str]) -> None:
        state.relays.pop(client_key, None)

    r.add_done_callback(_on_relay_done)
    return None


async def connect_handler(state: AppState, request: anet.http.Request, sock_name: str) -> anet.http.Response | None:
    token = verify_token(state, request)
    if token is None:
        return http.response(status_code=403)

    colon = request.resource_target.find(":")
    if colon == -1:
        logger.error("Invalid request resource_target: missing colon")
        return http.response(status_code=400)

    host = request.resource_target[:colon]
    port = request.resource_target[colon + 1 :]
    if not port.isdigit():
        logger.error("Invalid request resource_target: invalid port")
        return http.response(status_code=400)

    logger.info(f"Connect to {token.tenant_id}/{host}")
    client_key = (token.tenant_id, host)
    relay = state.relays.get(client_key)
    if relay is None:
        return http.problem_response(status_code=404, title="No relay found")

    sock = anet.sockets.store.get(sock_name)
    assert sock is not None
    await http.response(status_code=200).serialize(sock)

    await relay.open_connection(sock_name)
    return None


def create(conf: Config, state: AppState, sock: anet.base.Socket) -> http.Application[AppState]:
    app = http.Application[AppState](state, sock)
    app.add_route(http.Route[AppState](connect_handler, host=f"connect.{conf.domain_suffix}"))
    app.add_route(http.Route[AppState](register_handler, host=f"register.{conf.domain_suffix}"))
    return app
