import asyncio
import collections
import contextlib
import json
import logging
import time

import cryptography.fernet
import fastapi

from ... import bastion_visitor
from .. import dependencies, model
from ..context import ctx

logger = logging.getLogger(__name__)

router = fastapi.APIRouter(prefix="/ssh/gateway")

CLOSE_UNAUTHORIZED = 4401
CLOSE_UNREACHABLE = 4502
CLOSE_BUSY = 4429

FIRST_MESSAGE_TIMEOUT = 10
TUNNEL_OPEN_TIMEOUT = 15
MAX_FIRST_MESSAGE = 8192
MAX_FRAME = 65536
PENDING = ("pending", 0)


# TODO: counters live in this process. With several workers every limit is multiplied by the
# worker count: share them across workers or divide the limits.
class SessionCounter:
    def __init__(self) -> None:
        self._count: collections.Counter[tuple[str, int]] = collections.Counter()

    def acquire(self, key: tuple[str, int], limit: int) -> bool:
        if self._count[key] >= limit:
            return False
        self._count[key] += 1
        return True

    def release(self, key: tuple[str, int]) -> None:
        self._count[key] -= 1
        if self._count[key] <= 0:
            del self._count[key]


def _origin_allowed(websocket: fastapi.WebSocket) -> bool:
    origin = websocket.headers.get("origin")
    return origin is None or origin in websocket.app.state.config.gateway_allowed_origins


async def _read_first_message(websocket: fastapi.WebSocket) -> tuple[str, int] | None:
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), FIRST_MESSAGE_TIMEOUT)
        if len(raw) > MAX_FIRST_MESSAGE:
            return None
        message = json.loads(raw)
        token, bastion_id = message["token"], message["bastion_id"]
    except (TimeoutError, fastapi.WebSocketDisconnect, RuntimeError, ValueError, KeyError, TypeError):
        return None
    if not isinstance(token, str) or not isinstance(bastion_id, int) or isinstance(bastion_id, bool):
        return None
    return token, bastion_id


async def _authorize(
    websocket: fastapi.WebSocket, tenant_uuid: str, token: str, bastion_id: int
) -> tuple[model.bastion.ConnectClaims, model.bastion.Bastion] | None:
    try:
        async with dependencies.tenant_read(websocket, tenant_uuid):  # type: ignore[arg-type]
            claims = model.bastion.verify_connect_token(token)
            if claims is None:
                return None
            with ctx.set_identity_id(claims.identity_id):
                bastion = next((b for b in model.bastion.read_matching() if b.id == bastion_id), None)
    except Exception as e:
        logger.info(f"gateway: authorization failed tenant={tenant_uuid}: {e}")
        return None
    if bastion is None:
        return None
    return claims, bastion


class _Activity:
    def __init__(self) -> None:
        self.last = time.monotonic()

    def touch(self) -> None:
        self.last = time.monotonic()


async def _watch_idle(activity: _Activity, timeout: int) -> None:
    while True:
        remaining = activity.last + timeout - time.monotonic()
        if remaining <= 0:
            return
        await asyncio.sleep(remaining)


async def _forward_up(websocket: fastapi.WebSocket, tunnel: bastion_visitor.Tunnel, activity: _Activity) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        data = message.get("bytes")
        if data is None or len(data) > MAX_FRAME:
            return
        activity.touch()
        tunnel.writer.write(data)
        await tunnel.writer.drain()


async def _forward_down(websocket: fastapi.WebSocket, tunnel: bastion_visitor.Tunnel, activity: _Activity) -> None:
    while True:
        data = await tunnel.reader.read_some(MAX_FRAME)
        if len(data) == 0:
            return
        activity.touch()
        await websocket.send_bytes(data)


async def _forward(websocket: fastapi.WebSocket, tunnel: bastion_visitor.Tunnel, idle_timeout: int) -> None:
    activity = _Activity()
    tasks = [
        asyncio.create_task(_forward_up(websocket, tunnel, activity)),
        asyncio.create_task(_forward_down(websocket, tunnel, activity)),
        asyncio.create_task(_watch_idle(activity, idle_timeout)),
    ]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        tunnel.writer.close()


async def _handshake(
    websocket: fastapi.WebSocket, tenant_uuid: str
) -> tuple[model.bastion.ConnectClaims, model.bastion.Bastion, str] | None:
    sessions: SessionCounter = websocket.app.state.gateway_sessions
    if not sessions.acquire(PENDING, websocket.app.state.config.gateway_max_unauthenticated_sockets):
        await websocket.close(code=CLOSE_BUSY)
        return None
    try:
        await websocket.accept()
        first = await _read_first_message(websocket)
        if first is None:
            await websocket.close(code=CLOSE_UNAUTHORIZED)
            return None
        token, bastion_id = first
        kek = cryptography.fernet.Fernet(websocket.app.state.kek)
        with ctx.set_kek(kek), ctx.set_config(websocket.app.state.config):
            authorized = await _authorize(websocket, tenant_uuid, token, bastion_id)
        if authorized is None:
            await websocket.close(code=CLOSE_UNAUTHORIZED)
            return None
        return authorized[0], authorized[1], token
    finally:
        sessions.release(PENDING)


@router.websocket("/ws")
async def gateway_websocket(websocket: fastapi.WebSocket, tenant_uuid: str) -> None:
    if not _origin_allowed(websocket):
        await websocket.close(code=fastapi.status.WS_1008_POLICY_VIOLATION)
        return
    authenticated = await _handshake(websocket, tenant_uuid)
    if authenticated is None:
        return
    claims, bastion, token = authenticated

    sessions: SessionCounter = websocket.app.state.gateway_sessions
    key = (tenant_uuid, claims.identity_id)
    if not sessions.acquire(key, websocket.app.state.config.gateway_max_sessions_per_identity):
        await websocket.close(code=CLOSE_BUSY)
        return
    try:
        try:
            tunnel = await asyncio.wait_for(
                bastion_visitor.open_tunnel(bastion.url, claims.audience, token), TUNNEL_OPEN_TIMEOUT
            )
        except Exception as e:
            logger.info(f"gateway: bastion={bastion.url} unreachable connection_id={claims.connection_id}: {e}")
            await websocket.close(code=CLOSE_UNREACHABLE)
            return
        await _forward(websocket, tunnel, websocket.app.state.config.gateway_idle_timeout)
        with contextlib.suppress(Exception):
            await websocket.close()
    finally:
        sessions.release(key)
