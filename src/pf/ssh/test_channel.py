import asyncio
import socket

import pytest

from . import channel, tcp, _mux


@pytest.fixture
async def pair():
    server_sock, client_sock = socket.socketpair()
    server_async = tcp.TcpSocket(server_sock)
    client_async = tcp.TcpSocket(client_sock)

    server = channel.Server(server_async)
    client = channel.Client(client_async)
    yield server, client
    await server.close()
    await client.close()


@pytest.mark.anyio
async def test_channel_client_server_bidirectional(pair):
    """Test client-server channel communication."""
    server, client = pair

    async def server_task():
        # Accept channel
        ch = await server.accept()
        assert ch.channel_type == "session"

        # Read from client
        data = await ch.read()
        assert data == b"hello"

        # Write to client
        await ch.write(b"world")

        # Close
        await ch.close()

    async def client_task():
        # Open channel
        ch = await client.open_channel("session")
        assert ch.channel_type == "session"

        # Write to server
        await ch.write(b"hello")

        # Read from server
        data = await ch.read()
        assert data == b"world"

        # Read EOF
        data = await ch.read()
        assert data == b""

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_large_data(pair):
    """Test sending data larger than MAX_PACKET."""
    server, client = pair

    large_data = b"x" * (_mux.MAX_PACKET * 3 + 1000)

    async def server_task():
        ch = await server.accept()
        received = b""
        while True:
            data = await ch.read()
            if not data:
                break
            received += data
        assert received == large_data

    async def client_task():
        ch = await client.open_channel("session")
        await ch.write(large_data)
        await ch.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_multiple_channels(pair):
    """Test multiple concurrent channels."""
    server, client = pair

    channels_received = []

    async def server_task():
        for _ in range(3):
            ch = await server.accept()
            channels_received.append(ch.channel_type)
            data = await ch.read()
            await ch.write(data + b"_response")
            await ch.close()

    async def send_channel(c, i):
        ch = await c.open_channel(f"type_{i}")
        await ch.write(b"test")
        data = await ch.read()
        assert data == b"test_response"
        await ch.read()  # EOF

    async def client_task():
        tasks = []
        for i in range(3):
            tasks.append(send_channel(client, i))
        await asyncio.gather(*tasks)

    await asyncio.gather(server_task(), client_task())
    assert sorted(channels_received) == ["type_0", "type_1", "type_2"]


@pytest.mark.anyio
async def test_channel_empty_data(pair):
    """Test sending empty data."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        data = await ch.read()
        assert data == b""
        data = await ch.read()
        assert data == b""

    async def client_task():
        ch = await client.open_channel("session")
        await ch.write(b"")
        await ch.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_half_close_echo(pair):
    """Test half-close with echo (client -> server -> client)."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # Read from client
        data = await ch.read()
        assert data == b"ping"
        # Read EOF (client half-closed)
        data = await ch.read()
        assert data == b""
        # But we can still write
        await ch.write(b"pong")
        # Now close fully
        await ch.close()

    async def client_task():
        ch = await client.open_channel("session")
        # Send data
        await ch.write(b"ping")
        # Half-close write side
        await ch.close_write()
        # Can still read response
        data = await ch.read()
        assert data == b"pong"
        # Read EOF from server
        data = await ch.read()
        assert data == b""
        # Now close fully
        await ch.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_half_close_write_after_error(pair):
    """Test that writing after half-close raises error."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # Just wait for EOF
        while True:
            data = await ch.read()
            if not data:
                break

    async def client_task():
        ch = await client.open_channel("session")
        await ch.close_write()

        # Writing after half-close should fail
        try:
            await ch.write(b"fail")
            assert False, "Should have raised"
        except BaseException:  # exceptions.Error inherits from BaseException
            pass
        await ch.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_half_close_idempotent(pair):
    """Test that half-close can be called multiple times."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # Just wait for EOF
        while True:
            data = await ch.read()
            if not data:
                break

    async def client_task():
        ch = await client.open_channel("session")
        await ch.close_write()
        await ch.close_write()  # Should be idempotent
        await ch.close()
        await ch.close()  # Should be idempotent

    await asyncio.gather(server_task(), client_task())
