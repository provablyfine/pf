from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import time
import uuid

import asyncssh
import cryptography.fernet
import fastapi

from ... import bastion_visitor
from .. import dependencies, grant, model, schemas, shell_ticket
from ..context import ctx

logger = logging.getLogger(__name__)

router = fastapi.APIRouter(prefix="/ssh/shell")

_CLOSE_TICKET_INVALID = 4401
_CLOSE_FORBIDDEN = 4403
_CLOSE_UNREACHABLE = 4502
_CLOSE_SSH_FAILED = 4503


async def _redeem_ticket(websocket: fastapi.WebSocket, ticket: str | None) -> shell_ticket.Ticket | None:
    if ticket is None:
        await websocket.close(code=_CLOSE_TICKET_INVALID)
        return None
    redeemed_ticket = websocket.app.state.shell_ticket_store.redeem(ticket)
    if redeemed_ticket is None:
        await websocket.close(code=_CLOSE_TICKET_INVALID)
        return None
    return redeemed_ticket


def _mint_connect_tokens(ticket: shell_ticket.Ticket) -> list[tuple[schemas.bastion.Bastion, str]]:
    return [
        (
            bastion,
            model.bastion.generate_token(
                ticket.hostname, "connect", deadline=ticket.deadline, connection_id=ticket.connection_id
            ),
        )
        for bastion in ticket.bastion_list
        if bastion.url
    ]


async def _authorize_shell(
    websocket: fastapi.WebSocket, tenant_uuid: str, ticket: shell_ticket.Ticket
) -> tuple[bytes, list[tuple[schemas.bastion.Bastion, str]]] | None:
    async with dependencies.tenant_read(websocket, tenant_uuid):  # type: ignore[arg-type]
        with ctx.set_identity_id(ticket.identity_id), ctx.set_active_role_id(ticket.active_role_id):
            caller = model.identity.read_one(id=ticket.identity_id)
            host = model.identity.read_one(name=ticket.hostname)
            if caller is None or host is None:
                await websocket.close(code=_CLOSE_TICKET_INVALID)
                return None
            checker = grant.Grants.create().ssh(host.id, host.tag_id_list, host.boundary_id_list)
            decision = checker.decide(ticket.username, caller.unix_username)
            if model.grant.SSHCapability.SHELL not in decision.capabilities:
                await websocket.close(code=_CLOSE_FORBIDDEN)
                return None
            known_hosts = model.signing_key.read_host_trusted_keys_text()
            bastion_tokens = _mint_connect_tokens(ticket)
    return known_hosts, bastion_tokens


async def _dial_bastion(
    hostname: str, bastion_tokens: list[tuple[schemas.bastion.Bastion, str]]
) -> tuple[bastion_visitor.FrpReader, asyncio.StreamWriter] | None:
    for bastion, token in bastion_tokens:
        try:
            tunnel = await bastion_visitor.open_tunnel(bastion.url, hostname, token)
        except Exception as e:
            logger.info(f"shell: bastion={bastion.url} unreachable for hostname={hostname}: {e}")
            continue
        return tunnel.reader, tunnel.writer
    return None


async def _open_ssh_connection(
    ticket: shell_ticket.Ticket,
    tunnel_reader_writer: tuple[bastion_visitor.FrpReader, asyncio.StreamWriter],
    known_hosts: bytes,
) -> tuple[asyncssh.SSHClientConnection, asyncssh.SSHClientProcess[bytes]]:
    """Bridges the bastion tunnel into asyncssh over a loopback TCP pair.

    Not `socket.socketpair()`: that defaults to `AF_UNIX`, which has no `(host, port)`
    peer identity, and asyncssh's `_connection_made()` crashes without one.
    """
    tunnel_reader, tunnel_writer = tunnel_reader_writer
    loop = asyncio.get_running_loop()

    # One real TCP connection, entirely on loopback: asyncssh owns one end outright,
    # we drive the other end by hand. The listener's only job is introducing the two;
    # it's closed right after.
    loopback_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    loopback_listener.bind(("127.0.0.1", 0))
    loopback_listener.listen(1)
    tunnel_side_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tunnel_side_socket.connect(loopback_listener.getsockname())
    asyncssh_side_socket, _ = loopback_listener.accept()
    loopback_listener.close()
    tunnel_side_socket.setblocking(False)
    asyncssh_side_socket.setblocking(False)

    # The actual bridge: copy bytes between the bastion tunnel and our end of the pair,
    # in both directions, concurrently.
    async def pump_bastion_to_asyncssh() -> None:
        try:
            while True:
                data = await tunnel_reader.read_some(bastion_visitor.RECV_CHUNK_SIZE)
                if not data:
                    return
                await loop.sock_sendall(tunnel_side_socket, data)
        except (OSError, EOFError):
            return

    async def pump_asyncssh_to_bastion() -> None:
        try:
            while True:
                data = await loop.sock_recv(tunnel_side_socket, bastion_visitor.RECV_CHUNK_SIZE)
                if not data:
                    return
                tunnel_writer.write(data)
                await tunnel_writer.drain()
        except (OSError, ConnectionError):
            return

    bridge_tasks = [asyncio.create_task(pump_bastion_to_asyncssh()), asyncio.create_task(pump_asyncssh_to_bastion())]

    # The ticket's key material, in the formats asyncssh wants.
    private_key = asyncssh.import_private_key(ticket.private_key.to_openssh())
    client_cert = asyncssh.import_certificate(ticket.certificate)
    known_hosts_obj = asyncssh.import_known_hosts(known_hosts.decode("ascii"))

    # Hand asyncssh its end of the pair and do the real SSH handshake.
    try:
        conn = await asyncssh.connect(
            host=ticket.hostname,
            sock=asyncssh_side_socket,
            username=ticket.username,
            client_keys=[(private_key, client_cert)],
            known_hosts=known_hosts_obj,
        )
        process = await conn.create_process(term_type="xterm", term_size=(80, 24), encoding=None)
    except BaseException:
        # Handshake failed: nothing below ran, so the bridge would otherwise leak.
        for task in bridge_tasks:
            task.cancel()
        for task in bridge_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        tunnel_side_socket.close()
        raise

    # _close_ssh_connection needs these back later to tear the bridge down.
    conn._pf_bridge_tasks = bridge_tasks  # type: ignore[attr-defined]
    conn._pf_tunnel_side_socket = tunnel_side_socket  # type: ignore[attr-defined]
    return conn, process


async def _bridge_ssh(
    websocket: fastapi.WebSocket,
    ticket: shell_ticket.Ticket,
    tunnel_streams: tuple[bastion_visitor.FrpReader, asyncio.StreamWriter],
    known_hosts: bytes,
) -> tuple[asyncssh.SSHClientConnection, asyncssh.SSHClientProcess[bytes]] | None:
    try:
        return await _open_ssh_connection(ticket, tunnel_streams, known_hosts)
    except Exception:
        logger.exception(f"shell: ssh handshake failed for hostname={ticket.hostname}")
        await websocket.close(code=_CLOSE_SSH_FAILED)
        return None


async def _close_ssh_connection(conn: asyncssh.SSHClientConnection) -> None:
    for task in getattr(conn, "_pf_bridge_tasks", []):
        task.cancel()
    for task in getattr(conn, "_pf_bridge_tasks", []):
        with contextlib.suppress(asyncio.CancelledError):
            await task
    tunnel_side_socket = getattr(conn, "_pf_tunnel_side_socket", None)
    if tunnel_side_socket is not None:
        tunnel_side_socket.close()
    conn.close()


async def _report_live_start(
    websocket: fastapi.WebSocket, tenant_uuid: str, ticket: shell_ticket.Ticket, session_id: str
) -> None:
    async with dependencies.tenant_read(websocket, tenant_uuid):  # type: ignore[arg-type]
        model.live.start(
            connection_id=ticket.connection_id,
            hostname=ticket.hostname,
            kind="relay",
            session_id=session_id,
            at=int(time.time()),
        )


async def _report_live_end(
    websocket: fastapi.WebSocket, tenant_uuid: str, ticket: shell_ticket.Ticket, session_id: str
) -> None:
    async with dependencies.tenant_read(websocket, tenant_uuid):  # type: ignore[arg-type]
        model.live.end(
            connection_id=ticket.connection_id,
            hostname=ticket.hostname,
            kind="relay",
            session_id=session_id,
            at=int(time.time()),
        )


async def _pump(websocket: fastapi.WebSocket, process: asyncssh.SSHClientProcess[bytes]) -> None:
    async def input_to_ssh() -> None:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            data = message.get("bytes")
            if data is not None:
                process.stdin.write(data)
                continue
            text = message.get("text")
            if text is None:
                continue
            try:
                resize = json.loads(text)
                cols, rows = int(resize["cols"]), int(resize["rows"])
            except (ValueError, KeyError, TypeError):
                continue
            if 1 <= cols <= 1000 and 1 <= rows <= 1000:
                process.change_terminal_size(cols, rows)

    async def output_to_websocket() -> None:
        while True:
            data = await process.stdout.read(bastion_visitor.RECV_CHUNK_SIZE)
            if not data:
                return
            await websocket.send_bytes(data)

    tasks = [asyncio.create_task(input_to_ssh()), asyncio.create_task(output_to_websocket())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


async def _teardown(
    conn: asyncssh.SSHClientConnection,
    websocket: fastapi.WebSocket,
    tenant_uuid: str,
    ticket: shell_ticket.Ticket,
    session_id: str,
) -> None:
    await _close_ssh_connection(conn)
    with contextlib.suppress(Exception):
        await websocket.close()
    await _report_live_end(websocket, tenant_uuid, ticket, session_id)


@router.websocket("/ws")
async def shell_websocket(websocket: fastapi.WebSocket, tenant_uuid: str, ticket: str | None = None) -> None:
    await websocket.accept()

    redeemed_ticket = await _redeem_ticket(websocket, ticket)
    if redeemed_ticket is None:
        return

    kek = cryptography.fernet.Fernet(websocket.app.state.kek)
    with ctx.set_kek(kek), ctx.set_config(websocket.app.state.config):
        authorized = await _authorize_shell(websocket, tenant_uuid, redeemed_ticket)
        if authorized is None:
            return
        known_hosts, bastion_tokens = authorized

        tunnel_streams = await _dial_bastion(redeemed_ticket.hostname, bastion_tokens)
        if tunnel_streams is None:
            await websocket.close(code=_CLOSE_UNREACHABLE)
            return

        bridged = await _bridge_ssh(websocket, redeemed_ticket, tunnel_streams, known_hosts)
        if bridged is None:
            return
        conn, process = bridged

        session_id = str(uuid.uuid4())
        await _report_live_start(websocket, tenant_uuid, redeemed_ticket, session_id)

        try:
            await _pump(websocket, process)
        finally:
            await _teardown(conn, websocket, tenant_uuid, redeemed_ticket, session_id)
