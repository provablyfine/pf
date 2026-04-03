import asyncio
import contextlib
import dataclasses
import logging

import fastapi
import jwt

from . import mux

logger = logging.getLogger(__name__)

_403 = fastapi.HTTPException(status_code=403, detail="Invalid authorization")


@dataclasses.dataclass
class Config:
    dev_tenant_id: int | None
    dev_name: str | None
    issuer_prefix: str | None


class Client:
    def __init__(self, socket: fastapi.websockets.WebSocket):
        self._socket = socket


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
        self._client_by_iss = {}

    def lookup(self, token: str) -> TrustedKey:
        # we manually decode the token to extract the iss
        try:
            unverified = jwt.decode(token, options={"verify_signature": False, "require": ["iss", "kid"]})
        except jwt.exceptions.InvalidTokenError as e:
            logger.debug(f"Invalid token: {e}")
            raise _403

        iss, kid = unverified["iss"], unverified["kid"]

        # We manually validate the iss because we want to do a prefix match, not an exact
        # match because we have multiple tenants !
        if not iss.startswith(self._issuer_prefix):
            logger.debug(f"Invalid token: issuer does not match our prefix: {iss}!={self._issuer_prefix}")
            raise _403

        client = self._client_by_iss.get(iss)
        if client is None:
            client = jwt.PyJWKClient(iss)
            self._client_by_iss[iss] = client
        try:
            key = client.get_signing_key(kid)
        except jwt.exceptions.PyJWKClientError:
            logger.warning(
                f"Invalid key iss={iss} kid={kid}. "
                "Something is wrong with your key rotation or someone is trying to screw you."
            )
            raise _403

        return TrustedKey(issuer=iss, key=key)


def verify_token(ws: fastapi.websockets.WebSocket, expected_permission: str) -> Token:
    if ws.app.state.dev_tenant_id is not None and ws.app.state.dev_name is not None:
        return Token(tenant_id=ws.app.state.dev_tenant_id, name=ws.app.state.dev_name)

    if "Authorization" not in ws.headers:
        logger.debug("Missing Authorization header")
        raise _403
    authorization = ws.headers["Authorization"]
    space = authorization.find(" ")
    if space == -1:
        logger.debug("Invalid Authorization header")
        raise _403
    if authorization[:space] != "Bearer":
        logger.debug("Authorization header must contain a Bearer token")
        raise _403
    token = authorization[space + 1 :].strip(" ")

    trusted_key = ws.app.state.trusted_keys.lookup(token)

    try:
        payload = jwt.decode(
            token,
            trusted_key.key,
            algorithms=["EdDSA"],
            audience=ws.app.state.audience,
            issuer=trusted_key.issuer,
            options={"require": ["sub", "name", "permissions", "tenant_id"]},
        )
    except jwt.exceptions.InvalidTokenError as e:
        logger.debug(f"Invalid token: {e}")
        raise _403

    # Final checks before we declare victory
    if expected_permission not in payload["permissions"]:
        raise _403
    if not isinstance(payload["tenant_id"], int):
        logger.debug(f"Invalid token: tenant_id is not an integer: {payload['tenant_id']}")
        raise _403

    assert payload["tenant_id"] >= 1
    return Token(name=payload["name"], tenant_id=payload["tenant_id"])


router = fastapi.APIRouter()


@router.websocket("/register")
async def register(ws: fastapi.websockets.WebSocket) -> None:
    token = verify_token(ws, "register")

    await ws.accept(subprotocol="mux-ssh")

    logger.info(f"Registering identity {token.tenant_id}/{token.name}")
    client_key = (token.tenant_id, token.name)

    multiplexer = mux.Server(ws)
    try:
        ws.app.state.clients[client_key] = multiplexer
        await multiplexer.wait_closed()
    finally:
        await multiplexer.close()
        del ws.app.state.clients[client_key]
        await ws.close(code=1000)
    return None


async def _relay_ws_to_channel(ws: fastapi.WebSocket, ch: mux.Channel) -> None:
    """Forward messages from the local WebSocket to the mux channel."""
    try:
        while True:
            data = await ws.receive_bytes()
            await ch.send(data)
    except fastapi.WebSocketDisconnect:
        raise
    except Exception as exc:
        raise mux.ChannelError("ws->channel relay failed") from exc


async def _relay_channel_to_ws(ws: fastapi.WebSocket, ch: mux.Channel) -> None:
    """Forward messages from the mux channel to the local WebSocket."""
    try:
        while True:
            data = await ch.receive()
            await ws.send_bytes(data)
    except (mux.ChannelError, mux.MuxError):
        raise
    except Exception as exc:
        raise fastapi.WebSocketDisconnect() from exc


@router.websocket("/connect")
async def connect(ws: fastapi.websockets.WebSocket, hostname: str):
    token = verify_token(ws, "connect")
    client_key = (token.tenant_id, hostname)
    multiplexer = ws.app.state.clients.get(client_key)
    if multiplexer is None:
        await ws.close(code=404, reason="Hostname is not registered")
        return

    await ws.accept(subprotocol="ssh")

    ch = await multiplexer.open_channel()
    try:
        await asyncio.gather(
            _relay_ws_to_channel(ws, ch),
            _relay_channel_to_ws(ws, ch),
        )
    except (mux.ChannelError, mux.MuxError, fastapi.WebSocketDisconnect):
        pass
    finally:
        await ch.close()
        await ws.close()


def create(conf: Config) -> fastapi.FastAPI:
    @contextlib.asynccontextmanager
    async def lifespan(app: fastapi.FastAPI):

        app.state.trusted_keys = TrustedKeys(conf.issuer_prefix) if conf.issuer_prefix else None
        app.state.audience = "bastion"
        app.state.clients = {}
        app.state.dev_tenant_id = conf.dev_tenant_id
        app.state.dev_name = conf.dev_name
        yield

    fastapi_app = fastapi.FastAPI(lifespan=lifespan)
    fastapi_app.include_router(router)
    return fastapi_app
