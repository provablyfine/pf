import asyncio
import dataclasses
import json
import logging
import socket
import traceback
import typing

import jwt

from .. import anet, log
from . import exceptions

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


@dataclasses.dataclass
class AppState:
    trusted_keys: TrustedKeys | None
    audience: str
    dev_tenant_id: int | None
    dev_name: str | None
    clients: dict[tuple[int, str], anet.channel.Client]


@dataclasses.dataclass
class Response:
    status_code: int
    title: str | None


class HTTPException(Exception):
    def __init__(self, response: Response):
        self._response = response

    @property
    def response(self) -> Response:
        return self._response


RouteHandler = typing.Callable[[anet.base.Socket], typing.Awaitable[None]]
RouteChecker = typing.Callable[[AppState, Request], typing.Awaitable[RouteHandler]]


@dataclasses.dataclass
class Route:
    host: str
    check: RouteChecker


_400 = Response(status_code=400, title="Invalid request")
_403 = Response(status_code=404, title="Not Authorized")
_404 = Response(status_code=404, title="Resource not found")


def verify_token(state: AppState, request: Request) -> Token | None:
    if state.dev_tenant_id is not None and state.dev_name is not None:
        return Token(tenant_id=state.dev_tenant_id, name=state.dev_name)
    assert state.trusted_keys is not None

    if "Proxy-Authorization" not in request.headers:
        logger.debug("Missing Proxy-Authorization header")
        return None
    authorization = request.headers["Proxy-Authorization"]
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


async def register_checker(state: AppState, request: Request) -> RouteHandler:
    token = verify_token(state, request)
    if token is None:
        raise HTTPException(_403)

    logger.info(f"Registering identity {token.tenant_id}/{token.name}")
    client_key = (token.tenant_id, token.name)

    async def handler(sock: anet.base.Socket) -> None:
        client = anet.channel.Client(sock)
        try:
            state.clients[client_key] = client
            await client.wait_closed()
        finally:
            await client.close()
            del state.clients[client_key]
            try:
                await sock.close()
            except Exception:
                pass

    return handler


async def connect_checker(state: AppState, request: Request) -> RouteHandler:
    token = verify_token(state, request)
    if token is None:
        raise HTTPException(_403)

    client_key = (token.tenant_id, request.host)
    client = state.clients.get(client_key)
    if client is None:
        raise HTTPException(_404)

    async def handler(user: anet.base.Socket) -> None:
        host = await client.open_channel()

        async def relay_user_to_host() -> None:
            logger.debug("relay_user_to_host start")
            try:
                while True:
                    data = await user.recv(4096)
                    if data == b"":
                        # EOF
                        break
                    logger.debug(f"relay_user_to_host rx={len(data)}")
                    await host.write(data)
                    logger.debug(f"relay_user_to_host tx={len(data)}")
            except anet.exceptions.Error:
                pass
            finally:
                await host.close_write()

        async def relay_host_to_user() -> None:
            logger.debug("relay_host_to_user start")
            try:
                while True:
                    data = await host.read()
                    if data == b"":
                        # EOF
                        break
                    logger.debug(f"relay_host_to_user rx={len(data)}")
                    await user.send(data)
                    logger.debug(f"relay_host_to_user tx={len(data)}")
            except anet.exceptions.Error:
                pass
            finally:
                await user.shutdown(anet.base.Shut.WR)

        try:
            await asyncio.gather(
                relay_user_to_host(),
                relay_host_to_user(),
            )
        finally:
            await host.close()
            await user.close()

    return handler


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

    async def _parse_request(self, sock: anet.base.Socket) -> Request:
        # We can read the data via a local buffer because all the data
        # sent is only for the proxy until we send back a 200.
        reader = anet.stream.Reader(sock)
        start_line = await reader.read_until(b"\r\n")
        items = start_line.rstrip(b"\r\n").split(b" ")
        if len(items) != 3:
            logger.error("Invalid request start line")
            raise HTTPException(_400)
        method, resource_target, version = items
        if version != b"HTTP/1.1":
            logger.error("Invalid request HTTP version")
            raise HTTPException(_400)
        if method != b"CONNECT":
            logger.error("Invalid request HTTP method")
            raise HTTPException(_400)
        colon = resource_target.find(b":")
        if colon == -1:
            logger.error("Invalid request resource_target: missing colon")
            raise HTTPException(_400)
        host = resource_target[:colon]
        port = resource_target[colon + 1 :]
        if not port.isdigit():
            logger.error("Invalid request resource_target: invalid port")
            raise HTTPException(_400)
        headers: dict[str, str] = {}
        while True:
            line = await reader.read_until(b"\r\n")
            if line == b"\r\n":
                break
            colon = line.find(b":")
            if colon == -1:
                logger.error("Invalid request header: missing colon")
                raise HTTPException(_400)
            name = line[:colon].decode("ascii").lower()
            value = line[colon + 1 :].rstrip(b"\r\n").decode("ascii").lower()
            headers[name] = value
        request = Request(host=host.decode("ascii"), port=int(port), headers=headers)
        return request

    async def _handle_new_client(self, sock: anet.base.Socket) -> None:
        try:
            request = await self._parse_request(sock)
            if "host" not in request.headers:
                logger.error("Invalid request header: missing Host")
                raise HTTPException(_400)
            for route in self._routes:
                if request.headers["host"] == route.host:
                    handler = await route.check(self._state, request)
                    # Write back ok response
                    await sock.send("HTTP/1.1 200 OK\r\n".encode("ascii"))
                    # Take over connection
                    await handler(sock)
                    return
            logger.error(f"Unable to find route for host: {request.headers['host']}")
            response = _404
        except HTTPException as e:
            response = e.response
        except Exception:
            logger.error(traceback.format_exc())
            response = Response(status_code=500, title="Internal Server Error")
        else:
            assert False

        response_body = json.dumps({"title": response.title}).encode("utf-8")
        response_headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", len(response_body)),
        ]
        output: list[bytes] = ["HTTP/1.1 {response.status_code} {response.reason}\r\n".encode("ascii")]
        for name, value in response_headers:
            output.append(f"{name}: {value}\r\n".encode("ascii"))
        output.append("\r\n".encode("ascii"))
        output.append(response_body)
        await sock.send(b"".join(output))

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
    log.setup_server("bastion", conf.log_level, conf.log_filename)
    sock.setblocking(False)
    app = Application(conf, sock)
    app.add_route(Route(f"connect.{conf.domain_suffix}", connect_checker))
    app.add_route(Route(f"register.{conf.domain_suffix}", register_checker))
    return app
