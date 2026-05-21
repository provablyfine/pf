"""TLS/SSL socket tests for anet."""

from __future__ import annotations

import asyncio

import pytest

from . import base
from . import socket as anet_socket
from . import ssl as anet_ssl


@pytest.mark.anyio
async def test_ssl_listen_accept_handshake(
    ssl_contexts: tuple[anet_ssl.SSLContext, anet_ssl.SSLContext],
) -> None:
    """Full lifecycle: bind, listen, accept, handshake, exchange data."""
    server_ctx, client_ctx = ssl_contexts

    # Create raw listening socket, bind, and listen via SSL wrapper
    server_sock = anet_socket.socket(anet_socket.Family.INET, anet_socket.Type.STREAM)
    ssl_server: anet_ssl.Socket = await server_ctx.wrap_socket(server_sock, server_side=True)
    await ssl_server.bind(("127.0.0.1", 0))
    server_addr: tuple[str, int] = ssl_server.getsockname()
    await ssl_server.listen(1)

    # Client connect
    client_sock = anet_socket.socket(anet_socket.Family.INET, anet_socket.Type.STREAM)
    await client_sock.connect(server_addr)
    ssl_client: anet_ssl.Socket = await client_ctx.wrap_socket(client_sock, server_side=False, server_hostname=None)

    # Server accept returns a new SSL socket
    accepted_sock, _addr = await ssl_server.accept()
    assert isinstance(accepted_sock, anet_ssl.Socket)

    # Both sides perform handshake
    await asyncio.gather(accepted_sock.handshake(), ssl_client.handshake())

    # Exchange data
    test_data: bytes = b"listen-accept-test"
    await ssl_client.send(test_data)
    received = await accepted_sock.recv(65536)
    assert received == test_data

    # Cleanup
    ssl_client.close()
    accepted_sock.close()
    ssl_server.close()


@pytest.mark.anyio
async def test_ssl_handshake_bidirectional_echo(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """After handshake, exchange data over TLS."""
    client, server = tls_socketpair
    test_data = b"tls hello from client"

    async def server_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await server.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data
        await server.send(buf)

    async def client_task() -> None:
        await client.send(test_data)
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_ssl_large_data(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """Transfer 128 KiB over TLS."""
    client, server = tls_socketpair
    test_data = b"y" * (128 * 1024)

    async def server_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await server.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data
        await server.send(buf)

    async def client_task() -> None:
        await client.send(test_data)
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_ssl_clean_eof_via_close_notify(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """Client shutdown triggers TLS close_notify; server receives EOF."""
    client, server = tls_socketpair

    # Exchange one message
    await client.send(b"ping")
    received = await server.recv(65536)
    assert received == b"ping"

    # Client initiates TLS shutdown
    await client.shutdown(base.Shut.WR)

    # Server should receive EOF (triggered by SSLEOFError in recv)
    eof = await server.recv(65536)
    assert eof == b""


@pytest.mark.anyio
async def test_ssl_eof_during_handshake(
    anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket],
    ssl_contexts: tuple[anet_ssl.SSLContext, anet_ssl.SSLContext],
) -> None:
    """Close raw socket during TLS handshake; expect ConnectionError."""
    raw_client, raw_server = anet_socketpair
    _server_ctx, client_ctx = ssl_contexts

    ssl_client = await client_ctx.wrap_socket(raw_client, server_side=False, server_hostname=None)

    # Start client handshake
    client_task = asyncio.create_task(ssl_client.handshake())

    # Yield to let client start the handshake
    await asyncio.sleep(0)

    # Close the raw server socket before handshake completes
    raw_server.close()

    # Client handshake should raise ConnectionError
    with pytest.raises(ConnectionError):
        await client_task


@pytest.mark.anyio
async def test_ssl_recv_ignores_n(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """recv(n) ignores n and returns one full TLS record (design feature)."""
    client, server = tls_socketpair
    test_data = b"x" * 1000

    # Use a task to request recv while server is sending
    recv_task = asyncio.create_task(client.recv(1))
    await asyncio.sleep(0)  # Yield
    await server.send(test_data)

    record_data = await recv_task
    # Should receive all 1000 bytes, not just 1
    assert len(record_data) >= len(test_data)
    assert test_data in record_data  # The data should be in the record


@pytest.mark.anyio
async def test_ssl_recv_skips_protocol_records(tls_socketpair: tuple[anet_ssl.Socket, anet_ssl.Socket]) -> None:
    """recv loop handles protocol messages (e.g., session tickets) transparently."""
    client, server = tls_socketpair

    # Immediately after handshake, TLS 1.3 may send NewSessionTicket.
    # Calling recv on client should skip it and return data once server sends.
    test_data = b"hello after ticket"

    async def server_task() -> None:
        await asyncio.sleep(0.01)
        await server.send(test_data)

    async def client_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            if not chunk:
                break
            buf += chunk
        assert buf == test_data

    await asyncio.gather(client_task(), server_task())
