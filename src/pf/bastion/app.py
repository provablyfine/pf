import asyncio
import contextlib
import dataclasses
import logging
import sys

import fastapi
import jwt

from . import mux

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Config:
    dev_tenant_id: int | None
    dev_name: str | None
    issuer_prefix: str | None
    log_level: str = "WARNING"


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
            key = client.get_signing_key(kid)
        except jwt.exceptions.PyJWKClientError:
            logger.warning(
                f"Invalid key iss={iss} kid={kid}. "
                "Something is wrong with your key rotation or someone is trying to screw you."
            )
            return None

        return TrustedKey(issuer=iss, key=key)


def verify_token(ws: fastapi.websockets.WebSocket) -> Token | None:
    if ws.app.state.dev_tenant_id is not None and ws.app.state.dev_name is not None:
        return Token(tenant_id=ws.app.state.dev_tenant_id, name=ws.app.state.dev_name)

    if "Authorization" not in ws.headers:
        logger.debug("Missing Authorization header")
        return None
    authorization = ws.headers["Authorization"]
    space = authorization.find(" ")
    if space == -1:
        logger.debug("Invalid Authorization header")
        return None
    if authorization[:space] != "Bearer":
        logger.debug("Authorization header must contain a Bearer token")
        return None
    token = authorization[space + 1 :].strip(" ")

    trusted_key = ws.app.state.trusted_keys.lookup(token)
    if trusted_key is None:
        logger.error("Could not find matching trusted key")
        return None

    try:
        payload = jwt.decode(
            token,
            trusted_key.key,
            algorithms=["EdDSA"],
            audience=ws.app.state.audience,
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


router = fastapi.APIRouter()


@router.websocket("/register")
async def register(ws: fastapi.websockets.WebSocket) -> None:
    token = verify_token(ws)
    if token is None:
        await ws.close(code=1008)
        return

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
        try:
            await ws.close()
        except Exception:
            pass
    return None


@router.websocket("/connect")
async def connect(ws: fastapi.websockets.WebSocket, hostname: str):
    token = verify_token(ws)
    if token is None:
        await ws.close(code=1008)
        return

    client_key = (token.tenant_id, hostname)
    host_mux = ws.app.state.clients.get(client_key)
    if host_mux is None:
        await ws.close(code=1008, reason="Hostname is not registered")
        return

    await ws.accept(subprotocol="mux-ssh")

    user_mux = mux.Server(ws)
    user_ch = await user_mux.open_channel()
    host_ch = await host_mux.open_channel()

    async def relay_user_to_host() -> None:
        logger.debug("relay_user_to_host start")
        try:
            while True:
                data = await user_ch.receive()
                logger.debug(f"relay_user_to_host rx={len(data)}")
                await host_ch.send(data)
                logger.debug(f"relay_user_to_host tx={len(data)}")
        except (mux.ChannelError, mux.MuxError):
            pass
        finally:
            await host_ch.close()

    async def relay_host_to_user() -> None:
        logger.debug("relay_host_to_user start")
        try:
            while True:
                data = await host_ch.receive()
                logger.debug(f"relay_host_to_user rx={len(data)}")
                await user_ch.send(data)
                logger.debug(f"relay_host_to_user tx={len(data)}")
        except (mux.ChannelError, mux.MuxError):
            pass
        finally:
            await user_ch.close()

    try:
        await asyncio.gather(
            relay_user_to_host(),
            relay_host_to_user(),
        )
    except (mux.ChannelError, mux.MuxError):
        pass
    finally:
        await host_ch.close()
        await user_ch.close()
        await user_mux.close()
        try:
            await ws.close()
        except Exception:
            pass


def create(conf: Config) -> fastapi.FastAPI:
    @contextlib.asynccontextmanager
    async def lifespan(app: fastapi.FastAPI):

        app.state.trusted_keys = TrustedKeys(conf.issuer_prefix) if conf.issuer_prefix else None
        app.state.audience = "bastion"
        app.state.clients = {}
        app.state.dev_tenant_id = conf.dev_tenant_id
        app.state.dev_name = conf.dev_name
        yield

    match conf.log_level:
        case "DEBUG":
            level = logging.DEBUG
        case "INFO":
            level = logging.INFO
        case "WARNING":
            level = logging.WARN
        case "ERROR":
            level = logging.ERROR
        case _:
            assert False
    logging.basicConfig(stream=sys.stdout, level=level)

    fastapi_app = fastapi.FastAPI(lifespan=lifespan)
    fastapi_app.include_router(router)
    return fastapi_app
