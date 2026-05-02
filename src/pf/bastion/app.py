from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import socket
import traceback
import typing

import jwt

from .. import anet, log

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
class TrustedKey:
    issuer: str
    key: jwt.PyJWK


class TrustedKeys:
    def __init__(self, issuer_prefix: str):
        self._issuer_prefix = issuer_prefix
        self._client_by_iss: dict[str, jwt.PyJWKClient] = {}

    def lookup(self, token: str) -> TrustedKey | None:
        # we manually decode the token to extract the iss
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

        # We manually validate the iss because we want to do a prefix match, not an exact
        # match because we have multiple tenants !
        if not iss.startswith(self._issuer_prefix):
            logger.debug(f"Invalid token: issuer does not match our prefix: {iss}!={self._issuer_prefix}")
            return None

        client = self._client_by_iss.get(iss)
        if client is None:
            client = jwt.PyJWKClient(f"{iss}/.well-known/jwks.json")
            self._client_by_iss[iss] = client
        try:
            # XXX: should use async task ?
            key = client.get_signing_key(kid)
        except jwt.exceptions.PyJWKClientError:
            logger.warning(
                f"Invalid key iss={iss} kid={kid}. "
                "Something is wrong with your key rotation or someone is trying to screw you."
            )
            return None

        return TrustedKey(issuer=iss, key=key)


@dataclasses.dataclass
class Request:
    host: str
    port: int
    headers: dict[str, str]

    @classmethod
    async def deserialize(cls, sock: anet.base.Socket) -> Request:
        try:
            request = await anet.http.Request.deserialize(sock)
        except anet.exceptions.Error as exc:
            raise ValueError("Invalid HTTP request") from exc

        if request.version != "HTTP/1.1":
            logger.error("Invalid request HTTP version")
            raise ValueError("Invalid HTTP version")
        if request.method != "CONNECT":
            logger.error("Invalid request HTTP method")
            raise ValueError("Invalid HTTP method")
        colon = request.resource_target.find(":")
        if colon == -1:
            logger.error("Invalid request resource_target: missing colon")
            raise ValueError("Invalid resource target: missing colon")
        host = request.resource_target[:colon]
        port = request.resource_target[colon + 1 :]
        if not port.isdigit():
            logger.error("Invalid request resource_target: invalid port")
            raise ValueError("Invalid port")
        request = Request(host=host, port=int(port), headers=request.headers)
        return request


@dataclasses.dataclass
class Response:
    status_code: int
    title: str | None = None

    def _reason(self) -> str:
        mapping = {
            200: "OK",
            400: "Bad Request",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
        }
        return mapping.get(self.status_code, "Unexpected")

    async def serialize(self, sock: anet.base.Socket):
        if self.title is not None:
            response_body = json.dumps({"title": self.title}).encode("utf-8")
            response_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(response_body)),
            }
        else:
            response_headers = {}
            response_body = b""
        response = anet.http.Response(
            status_code=self.status_code,
            reason=self._reason(),
            version="HTTP/1.1",
            headers=response_headers,
            body=response_body,
        )
        await response.serialize(sock)


class Relay:
    """Manages a registered bastion client. Owns anet.channel.Client."""

    def __init__(
        self,
        socket_name: str,
        client_key: tuple[int, str],
        clients: dict[tuple[int, str], Relay],
    ) -> None:
        self._socket_name = socket_name
        self._client_key = client_key
        self._clients = clients
        self._client = anet.channel.Client(socket_name)

    async def open_connection(self, socket_name: str) -> RelayConnection:
        """Open a new connection through this relay."""
        host = await self._client.open_channel()
        return RelayConnection(socket_name, host)

    async def run(self) -> None:
        """Wait for client to close and clean up."""
        try:
            await self._client.wait_closed()
        finally:
            await self._client.close()
            del self._clients[self._client_key]
            anet.sockets.store.remove(self._socket_name)


class RelayConnection:
    """Relays data between user socket and a channel opened through Relay."""

    def __init__(self, socket_name: str, host: anet.channel.Channel) -> None:
        self._socket_name = socket_name
        self._host = host
        sock = anet.sockets.store.get(socket_name)
        assert sock is not None
        self._sock = sock

    async def run(self) -> None:
        """Relay data between socket and channel."""

        async def user_to_host() -> None:
            logger.debug("relay_user_to_host start")
            try:
                while True:
                    data = await self._sock.recv(4096)
                    if data == b"":
                        break
                    logger.debug(f"relay_user_to_host rx={len(data)}")
                    await self._host.write(data)
                    logger.debug(f"relay_user_to_host tx={len(data)}")
            except anet.exceptions.Error:
                pass
            finally:
                await self._host.close_write()

        async def host_to_user() -> None:
            logger.debug("relay_host_to_user start")
            try:
                while True:
                    data = await self._host.read()
                    if data == b"":
                        break
                    logger.debug(f"relay_host_to_user rx={len(data)}")
                    await self._sock.send(data)
                    logger.debug(f"relay_host_to_user tx={len(data)}")
            except anet.exceptions.Error:
                pass
            finally:
                await self._sock.shutdown(anet.base.Shut.WR)

        try:
            await asyncio.gather(user_to_host(), host_to_user())
        finally:
            await self._host.close()
            anet.sockets.store.remove(self._socket_name)
            await self._sock.close()


@dataclasses.dataclass
class AppState:
    trusted_keys: TrustedKeys | None
    audience: str
    dev_tenant_id: int | None
    dev_name: str | None
    clients: dict[tuple[int, str], Relay]


RouteHandler = typing.Callable[[AppState, Request, anet.base.Socket], typing.Awaitable[None]]


@dataclasses.dataclass
class Route:
    host: str
    handler: RouteHandler


_200 = Response(status_code=200)
_400 = Response(status_code=400, title="Invalid request")
_403 = Response(status_code=403, title="Not Authorized")
_404 = Response(status_code=404, title="Resource not found")


def _log_task_error(task: asyncio.Task[None]) -> None:
    if not task.cancelled() and task.exception() is not None:
        logger.error("Connection task failed", exc_info=task.exception())


def verify_token(state: AppState, request: Request) -> Token | None:
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


async def register_handler(state: AppState, request: Request, sock: anet.base.Socket) -> None:
    token = verify_token(state, request)
    if token is None:
        await _403.serialize(sock)
        await sock.close()
        return

    logger.info(f"Registering identity {token.tenant_id}/{token.name}")
    client_key = (token.tenant_id, token.name)
    socket_name = f"relay-register-{id(sock)}"
    anet.sockets.store.add(socket_name, sock)
    relay = Relay(socket_name, client_key, state.clients)
    state.clients[client_key] = relay
    await _200.serialize(sock)
    task = asyncio.create_task(relay.run())
    task.add_done_callback(_log_task_error)


async def connect_handler(state: AppState, request: Request, sock: anet.base.Socket) -> None:
    token = verify_token(state, request)
    if token is None:
        await _403.serialize(sock)
        await sock.close()
        return

    logger.info(f"Connect to {token.tenant_id}/{request.host}")
    client_key = (token.tenant_id, request.host)
    relay = state.clients.get(client_key)
    if relay is None:
        await _404.serialize(sock)
        await sock.close()
        return

    socket_name = f"relay-connect-{id(sock)}"
    anet.sockets.store.add(socket_name, sock)
    await _200.serialize(sock)
    connection = await relay.open_connection(socket_name)
    task = asyncio.create_task(connection.run())
    task.add_done_callback(_log_task_error)


class Application:
    def __init__(self, conf: Config, sock: socket.socket):
        self._config = conf
        self._state = AppState(
            trusted_keys=TrustedKeys(conf.issuer_prefix) if conf.issuer_prefix else None,
            audience="bastion",
            dev_tenant_id=conf.dev_tenant_id,
            dev_name=conf.dev_name,
            clients={},
        )
        self._raw_sock = sock
        self._sock: anet.base.Socket | None = None
        self._tasks: list[asyncio.Task[None]] = []
        self._routes: list[Route] = []

    def add_route(self, route: Route):
        self._routes.append(route)

    async def _handle_new_client(self, sock: anet.base.Socket) -> None:
        try:
            request = await Request.deserialize(sock)
        except Exception:
            logger.error(traceback.format_exc())
            await _400.serialize(sock)
            await sock.close()
            return

        if "host" not in request.headers:
            logger.error("Invalid request header: missing Host")
            await _400.serialize(sock)
            await sock.close()
            return

        for route in self._routes:
            if request.headers["host"] == route.host:
                await route.handler(self._state, request, sock)
                return

        logger.error(f"Unable to find route for host: {request.headers['host']}")
        await _404.serialize(sock)
        await sock.close()

    async def _loop(self) -> None:
        self._sock = anet.socket.Socket(self._raw_sock, loop=None)
        await self._sock.listen(10)
        while True:
            try:
                sock, _address = await self._sock.accept()
                task = asyncio.create_task(self._handle_new_client(sock))
                self._tasks.append(task)
            except OSError:
                # Socket closed by stop()
                break

    async def run(self):
        task = asyncio.create_task(self._loop())
        await task
        for task in self._tasks:
            task.cancel()

    def stop(self) -> None:
        self._raw_sock.close()


def create(conf: Config, sock: socket.socket) -> Application:
    log.setup_server("pf-bastion", conf.log_level, conf.log_filename)
    sock.setblocking(False)
    app = Application(conf, sock)
    app.add_route(Route(f"connect.{conf.domain_suffix}", connect_handler))
    app.add_route(Route(f"register.{conf.domain_suffix}", register_handler))
    return app
