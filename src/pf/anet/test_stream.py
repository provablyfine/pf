"""Stream reader tests for anet."""

from __future__ import annotations

import asyncio

import pytest

import pf.anet.socket as anet_socket
import pf.anet.ssl as anet_ssl
import pf.anet.stream as stream

SocketPair = tuple[anet_socket.Socket, anet_socket.Socket]
SSLSocketPair = tuple[anet_ssl.Socket, anet_ssl.Socket]


@pytest.mark.anyio
async def test_stream_read_until_single_recv(anet_socketpair: SocketPair) -> None:
    """read_until finds delimiter in single recv."""
    client, server = anet_socketpair
    test_line = b"hello\n"

    read_task = asyncio.create_task(stream.Reader(client).read_until(b"\n"))
    await asyncio.sleep(0)
    await server.send(test_line)
    result = await read_task
    assert result == test_line


@pytest.mark.anyio
async def test_stream_read_until_spanning_recvs(anet_socketpair: SocketPair) -> None:
    """read_until finds delimiter spanning multiple recvs."""
    client, server = anet_socketpair
    chunk1 = b"hel"
    chunk2 = b"lo\nworld"

    async def server_send_chunks() -> None:
        await server.send(chunk1)
        await asyncio.sleep(0.01)
        await server.send(chunk2)

    reader = stream.Reader(client)
    read_task = asyncio.create_task(reader.read_until(b"\n"))
    await asyncio.sleep(0)
    await server_send_chunks()
    result = await read_task
    assert result == b"hello\n"


@pytest.mark.anyio
async def test_stream_read_until_eof_before_delimiter(
    anet_socketpair: SocketPair,
) -> None:
    """read_until raises IncompleteReadError if EOF before delimiter."""
    client, server = anet_socketpair

    async def server_close() -> None:
        await server.send(b"no newline here")
        await server.close()

    async def client_read() -> None:
        reader = stream.Reader(client)
        with pytest.raises(stream.IncompleteReadError):
            await reader.read_until(b"\n")

    await asyncio.gather(client_read(), server_close())


@pytest.mark.anyio
async def test_stream_read_until_multiple_sequential(
    anet_socketpair: SocketPair,
) -> None:
    """Multiple sequential read_until calls consume buffer correctly."""
    client, server = anet_socketpair
    test_data = b"line1\nline2\nline3\n"

    async def client_task() -> None:
        reader = stream.Reader(client)
        line1 = await reader.read_until(b"\n")
        assert line1 == b"line1\n"
        line2 = await reader.read_until(b"\n")
        assert line2 == b"line2\n"
        line3 = await reader.read_until(b"\n")
        assert line3 == b"line3\n"

    async def server_task() -> None:
        await server.send(test_data)

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_stream_read_until_remainder_buffered(
    anet_socketpair: SocketPair,
) -> None:
    """read_until leaves remainder in buffer for next call."""
    client, server = anet_socketpair
    test_data = b"AAAA\nBBBB\n"

    async def client_task() -> None:
        reader = stream.Reader(client)
        first = await reader.read_until(b"\n")
        assert first == b"AAAA\n"
        # BBBB\n is now in the reader's buffer; no more socket recv needed
        second = await reader.read_until(b"\n")
        assert second == b"BBBB\n"

    async def server_task() -> None:
        await server.send(test_data)

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_stream_read_until_plain_socket(anet_socketpair: SocketPair) -> None:
    """read_until works with plain anet.socket.Socket."""
    client, server = anet_socketpair
    test_line = b"plain socket\n"

    read_task = asyncio.create_task(stream.Reader(client).read_until(b"\n"))
    await asyncio.sleep(0)
    await server.send(test_line)
    result = await read_task
    assert result == test_line


@pytest.mark.anyio
async def test_stream_read_until_ssl_socket(tls_socketpair: SSLSocketPair) -> None:
    """read_until works with TLS anet.ssl.Socket."""
    client, server = tls_socketpair
    test_line = b"tls data\n"

    read_task = asyncio.create_task(stream.Reader(client).read_until(b"\n"))
    await asyncio.sleep(0)
    await server.send(test_line)
    result = await read_task
    assert result == test_line


# ===== Stream Reader.read() Tests =====


@pytest.mark.anyio
async def test_stream_read_exact_bytes(anet_socketpair: SocketPair) -> None:
    """read(n) returns exactly n bytes."""
    client, server = anet_socketpair
    test_data = b"0123456789"

    read_task = asyncio.create_task(stream.Reader(client).read(5))
    await asyncio.sleep(0)
    await server.send(test_data)
    result = await read_task
    assert result == b"01234"


@pytest.mark.anyio
async def test_stream_read_spanning_recvs(anet_socketpair: SocketPair) -> None:
    """read(n) assembles data from multiple recvs."""
    client, server = anet_socketpair

    async def server_send_chunks() -> None:
        await server.send(b"hello")
        await asyncio.sleep(0.01)
        await server.send(b"world")

    reader = stream.Reader(client)
    read_task = asyncio.create_task(reader.read(10))
    await asyncio.sleep(0)
    await server_send_chunks()
    result = await read_task
    assert result == b"helloworld"


@pytest.mark.anyio
async def test_stream_read_leaves_remainder(anet_socketpair: SocketPair) -> None:
    """read(n) leaves remainder in buffer for next call."""
    client, server = anet_socketpair
    test_data = b"ABCDEFGHIJ"

    async def client_task() -> None:
        reader = stream.Reader(client)
        first = await reader.read(3)
        assert first == b"ABC"
        # Rest is buffered
        second = await reader.read(7)
        assert second == b"DEFGHIJ"

    async def server_task() -> None:
        await server.send(test_data)

    await asyncio.gather(client_task(), server_task())


@pytest.mark.anyio
async def test_stream_read_eof_before_n_bytes(anet_socketpair: SocketPair) -> None:
    """read(n) raises IncompleteReadError if EOF before n bytes."""
    client, server = anet_socketpair

    async def server_close() -> None:
        await server.send(b"short")
        await server.close()

    async def client_read() -> None:
        reader = stream.Reader(client)
        with pytest.raises(stream.IncompleteReadError):
            await reader.read(100)

    await asyncio.gather(client_read(), server_close())


@pytest.mark.anyio
async def test_stream_read_zero_bytes(anet_socketpair: SocketPair) -> None:
    """read(0) returns empty bytes immediately."""
    client, _server = anet_socketpair

    reader = stream.Reader(client)
    result = await reader.read(0)
    assert result == b""


@pytest.mark.anyio
async def test_stream_read_mixed_with_read_until(anet_socketpair: SocketPair) -> None:
    """read() and read_until() can be mixed."""
    client, server = anet_socketpair

    async def client_task() -> None:
        reader = stream.Reader(client)
        # read_until for line
        line = await reader.read_until(b"\n")
        assert line == b"hello\n"
        # read for exact bytes
        data = await reader.read(5)
        assert data == b"world"

    async def server_task() -> None:
        await server.send(b"hello\nworld123")

    await asyncio.gather(client_task(), server_task())
