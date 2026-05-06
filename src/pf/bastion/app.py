from __future__ import annotations

import dataclasses
import logging
import typing

import jwt

from .. import anet, log
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


@dataclasses.dataclass
class AppSnapshot:
    """Snapshot of full application relay state."""

    relays: list[relay.RelaySnapshot]

    def socket_names(self) -> list[str]:
        """All socket names referenced. Caller must transfer these FDs before restore."""
        names: list[str] = []
        for r in self.relays:
            names.append(r.socket_name)
            for c in r.connections:
                names.append(c.socket_name)
        return names

    def to_dict(self) -> dict[str, typing.Any]:
        """Serialize to dict."""
        return {"relays": [r.to_dict() for r in self.relays]}

    @classmethod
    def from_dict(cls, d: dict[str, typing.Any]) -> AppSnapshot:
        """Deserialize from dict."""
        return cls(relays=[relay.RelaySnapshot.from_dict(r) for r in d["relays"]])

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
        

    async def snapshot(self) -> AppSnapshot:
        relay_snapshots = [await relay.snapshot() for relay in list(self.relays.values())]
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


async def register_handler(state: AppState, request: anet.http.Request, sock: anet.base.Socket) -> None:
    token = verify_token(state, request)
    if token is None:
        await http.Response(status_code=403).serialize(sock)
        await sock.close()
        return

    logger.info(f"Registering identity {token.tenant_id}/{token.name}")
    client_key = (token.tenant_id, token.name)
    socket_name = f"relay-register-{id(sock)}"
    anet.sockets.store.add(socket_name, sock)
    await http.Response(status_code=200).serialize(sock)
    r = relay.Relay.start(socket_name, client_key)
    state.relays[client_key] = r

    def _on_relay_done(client_key: tuple[int, str]) -> None:
        state.relays.pop(client_key, None)
    r.add_done_callback(_on_relay_done)


async def connect_handler(state: AppState, request: anet.http.Request, sock: anet.base.Socket) -> None:
    token = verify_token(state, request)
    if token is None:
        await http.Response(status_code=403).serialize(sock)
        await sock.close()
        return

    colon = request.resource_target.find(":")
    if colon == -1:
        logger.error("Invalid request resource_target: missing colon")
        await http.Response(status_code=400).serialize(sock)
        await sock.close()
        return

    host = request.resource_target[:colon]
    port = request.resource_target[colon + 1 :]
    if not port.isdigit():
        logger.error("Invalid request resource_target: invalid port")
        await http.Response(status_code=400).serialize(sock)
        await sock.close()
        return

    logger.info(f"Connect to {token.tenant_id}/{host}")
    client_key = (token.tenant_id, host)
    relay = state.relays.get(client_key)
    if relay is None:
        await http.Response(status_code=404, title="No relay found").serialize(sock)
        await sock.close()
        return

    socket_name = f"relay-connect-{id(sock)}"
    anet.sockets.store.add(socket_name, sock)
    await http.Response(status_code=200).serialize(sock)
    await relay.open_connection(socket_name)


def create(conf: Config, state: AppState, sock: anet.socket.Socket) -> http.Application[AppState]:
    log.setup_server("pf-bastion", conf.log_level, conf.log_filename)
    app = http.Application[AppState](state, sock)
    app.add_route(http.Route[AppState](connect_handler, host=f"connect.{conf.domain_suffix}"))
    app.add_route(http.Route[AppState](register_handler, host=f"register.{conf.domain_suffix}"))
    return app
