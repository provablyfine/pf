"""Plain socket tests for anet."""

from __future__ import annotations

import pytest

import pf.anet.base as base
import pf.anet.socket as anet_socket


@pytest.mark.anyio
async def test_socket_bidirectional_echo(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Client sends data, server echoes it back."""
    client, server = anet_socketpair
    test_data = b"hello from client"

    await client.send(test_data)
    received = await server.recv(4096)
    assert received == test_data
    await server.send(test_data)
    echoed = await client.recv(4096)
    assert echoed == test_data


@pytest.mark.anyio
async def test_socket_large_data(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Transfer 256 KiB of data bidirectionally."""
    client, server = anet_socketpair
    test_data = b"x" * (256 * 1024)

    async def server_task() -> None:
        buf = b""
        while len(buf) < len(test_data):
            chunk = await server.recv(65536)
            assert chunk, "Server received EOF before all data"
            buf += chunk
        assert buf == test_data
        await server.send(buf)

    async def client_task() -> None:
        await client.send(test_data)
        # Receive echo
        buf = b""
        while len(buf) < len(test_data):
            chunk = await client.recv(65536)
            assert chunk, "Client received EOF before echo"
            buf += chunk
        assert buf == test_data

    import asyncio

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_socket_eof_on_close(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """Close socket; peer should recv b''."""
    client, server = anet_socketpair
    await client.send(b"ping")
    received = await server.recv(4096)
    assert received == b"ping"

    await client.close()
    eof = await server.recv(4096)
    assert eof == b""


@pytest.mark.anyio
async def test_socket_shutdown_wr_causes_eof(anet_socketpair: tuple[anet_socket.Socket, anet_socket.Socket]) -> None:
    """shutdown(SHUT_WR) signals EOF to peer; reverse direction still works."""
    client, server = anet_socketpair

    # Client half-closes write side
    await client.shutdown(base.Shut.WR)

    # Server should recv EOF
    eof = await server.recv(4096)
    assert eof == b""

    # But server can still send
    await server.send(b"still works")
    response = await client.recv(4096)
    assert response == b"still works"


@pytest.mark.anyio
async def test_socket_ipv4_loopback_echo() -> None:
    """Real TCP on 127.0.0.1 with listen/accept/connect."""
    # Server: create socket, bind, listen
    server_sock = await anet_socket.socket(anet_socket.Family.INET, anet_socket.Type.STREAM)
    await server_sock.bind(("127.0.0.1", 0))
    await server_sock.listen(1)
    server_addr = server_sock.getsockname()

    # Client: create socket, connect
    client_sock = await anet_socket.socket(anet_socket.Family.INET, anet_socket.Type.STREAM)
    await client_sock.connect(server_addr)

    # Server: accept connection
    accepted, _ = await server_sock.accept()

    # Exchange data
    test_data = b"ipv4-test"
    await client_sock.send(test_data)
    received = await accepted.recv(4096)
    assert received == test_data

    # Cleanup
    await client_sock.close()
    await accepted.close()
    await server_sock.close()


def _ipv6_available() -> bool:
    """Check if IPv6 is available."""
    import socket as _socket

    try:
        s = _socket.socket(_socket.AF_INET6, _socket.SOCK_STREAM)
        s.close()
        return True
    except OSError:
        return False


@pytest.mark.anyio
@pytest.mark.skipif(not _ipv6_available(), reason="IPv6 not available")
async def test_socket_ipv6_loopback_echo() -> None:
    """Real TCP on ::1 with listen/accept/connect."""
    # Server: create socket, bind, listen
    server_sock = await anet_socket.socket(anet_socket.Family.INET6, anet_socket.Type.STREAM)
    await server_sock.bind(("::1", 0, 0, 0))
    await server_sock.listen(1)
    server_addr = server_sock.getsockname()

    # Client: create socket, connect
    client_sock = await anet_socket.socket(anet_socket.Family.INET6, anet_socket.Type.STREAM)
    await client_sock.connect(server_addr)

    # Server: accept connection
    accepted, _ = await server_sock.accept()

    # Exchange data
    test_data = b"ipv6-test"
    await client_sock.send(test_data)
    received = await accepted.recv(4096)
    assert received == test_data

    # Cleanup
    await client_sock.close()
    await accepted.close()
    await server_sock.close()
