import argparse
import asyncio
import contextlib
import logging
import socket
import typing

import fastapi
import fastapi.requests
import fastapi.responses
import jose.jwt
import uvicorn

from .. import jwk

logger = logging.getLogger(__name__)


class BastionServer:
    def __init__(self, bastion_id: int, public_key_pem: bytes):
        self.bastion_id = bastion_id
        self.public_key = jwk.Public.from_pem(public_key_pem)
        self.identity_map: dict[str, tuple[str, int]] = {}

    def resolve_host(self, host: str) -> tuple[str, int] | None:
        return self.identity_map.get(host)

    def verify_token(self, token: str) -> int | None:
        try:
            payload = jose.jwt.decode(
                token,
                self.public_key.to_crypto(),
                algorithms=["EdDSA"],
                options={"verify_aud": False},
            )
            audience = payload.get("aud", "")
            if not audience.startswith("bastion:"):
                return None
            bastion_id = int(audience.split(":")[1])
            if bastion_id != self.bastion_id:
                return None
            return int(payload.get("sub", "0"))
        except Exception as e:
            logger.debug(f"Token verification failed: {e}")
            return None


router = fastapi.APIRouter()


@router.websocket("/register")
async def register(ws: fastapi.websockets.WebSocket, request: fastapi.requests.Request):
    await ws.accept(subprotocol="h2")
    token = ws.headers.get("authorization", "").replace("Bearer ", "")
    server = request.app.state.bastion
    identity_id = server.verify_token(token)
    if identity_id is None:
        await ws.close(code=4001, reason="Invalid token")
        return

    logger.info(f"Registering identity {identity_id}")
    server.identity_map[str(identity_id)] = ("127.0.0.1", 22)

    from ..tunnel import server as tunnel_server

    await tunnel_server.serve(ws, "", server.resolve_host)


@router.api_route("/connect/{hostname}", methods=["CONNECT"])
async def connect(hostname: str, request: fastapi.requests.Request):
    server = request.app.state.bastion
    target = server.resolve_host(hostname)
    if target is None:
        return fastapi.responses.JSONResponse(
            status_code=404,
            content={"error": "Identity not found"},
        )

    host, port = target

    reader, writer = await asyncio.open_connection(host, port)

    async def forward() -> typing.AsyncGenerator[bytes, None]:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                yield data
        except Exception as e:
            logger.debug(f"Forward error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    return fastapi.responses.StreamingResponse(
        forward(),
        media_type="application/octet-stream",
        status_code=200,
    )


def create(conf) -> fastapi.FastAPI:
    @contextlib.asynccontextmanager
    async def lifespan(app: fastapi.FastAPI):
        app.state.bastion = BastionServer(conf.bastion_id, conf.public_key_pem)
        yield

    fastapi_app = fastapi.FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)
    fastapi_app.include_router(router)
    return fastapi_app


class AppConfig:
    def __init__(self, bastion_id: int, public_key_pem: bytes, port: int, port_file: str | None):
        self.bastion_id = bastion_id
        self.public_key_pem = public_key_pem
        self.port = port
        self.port_file = port_file


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", type=int, required=True, help="Bastion ID")
    parser.add_argument("--signing-public-key", required=True, help="Public key file to verify tokens")
    parser.add_argument("-p", "--port", type=int, default=0)
    parser.add_argument("--port-file", default=None)
    args = parser.parse_args()

    with open(args.signing_public_key, "rb") as f:
        public_key_pem = f.read()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))

    host, port = sock.getsockname()

    if args.port_file is not None:
        with open(args.port_file, "w+") as f:
            f.write(str(port))

    conf = AppConfig(args.id, public_key_pem, port, args.port_file)
    app = create(conf)

    print(f"Starting Bastion on {host}:{port} using FD {sock.fileno()}")

    uvicorn.run(app, fd=sock.fileno(), log_level="info")
