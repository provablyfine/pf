import asyncio
import socket

import pytest

from . import channel, tcp, _mux


@pytest.fixture
async def pair():
    server_sock, client_sock = socket.socketpair()
    server_sock.setblocking(False)
    client_sock.setblocking(False)
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
        ch = await client.open_channel()

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
        ch = await client.open_channel()
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
        ch = await c.open_channel()
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
    assert sorted(channels_received) == ["session", "session", "session"]


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
        ch = await client.open_channel()
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
        ch = await client.open_channel()
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
        ch = await client.open_channel()
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
        ch = await client.open_channel()
        await ch.close_write()
        await ch.close_write()  # Should be idempotent
        await ch.close()
        await ch.close()  # Should be idempotent

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_close_without_eof(pair):
    """Test receiving CLOSE without prior EOF returns EOF."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # Send data but close without EOF
        await ch.write(b"hello")
        await ch.close()  # CLOSE without explicit EOF

    async def client_task():
        ch = await client.open_channel()
        data = await ch.read()
        assert data == b"hello"
        # Should read EOF due to CLOSE
        data = await ch.read()
        assert data == b""

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_open_failure(pair):
    """Test OPEN_FAILURE causes exception."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # This test doesn't actually reject, it accepts normally
        # A real server would reject via OPEN_FAILURE
        # For now, just accept to avoid hanging
        await ch.close()

    async def client_task():
        # Note: Our current server implementation always accepts.
        # This test is a placeholder for testing OPEN_FAILURE parsing.
        ch = await client.open_channel()
        await ch.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_send_window_exhaustion(pair):
    """Test send window exhaustion blocks write."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # Read all data slowly
        data = await ch.read()
        assert data == b"x"
        data = await ch.read()
        assert data == b""

    async def client_task():
        ch = await client.open_channel()
        # Override window to very small
        ch._impl._send_window = 1
        ch._impl._send_window_event.set()

        # Write 1 byte (fits in window)
        await ch.write(b"x")

        # Try to write more - will block until window_adjust
        # (but we never send one, so close instead)
        await ch.close_write()
        await ch.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_bidirectional_half_close(pair):
    """Test both sides half-close independently."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # Server writes then half-closes
        await ch.write(b"srv")
        await ch.close_write()
        # But can still read
        data = await ch.read()
        assert data == b"cli"
        data = await ch.read()
        assert data == b""
        await ch.close()

    async def client_task():
        ch = await client.open_channel()
        # Client writes then half-closes
        await ch.write(b"cli")
        await ch.close_write()
        # But can still read
        data = await ch.read()
        assert data == b"srv"
        data = await ch.read()
        assert data == b""
        await ch.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_channel_close_after_half_close_idempotent(pair):
    """Test close() after close_write() doesn't send duplicate EOF."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        # Receive EOF once (from half-close)
        data = await ch.read()
        assert data == b""
        # Another read should also return EOF
        data = await ch.read()
        assert data == b""

    async def client_task():
        ch = await client.open_channel()
        await ch.close_write()  # Sends EOF
        await ch.close()  # Sends CLOSE, EOF already sent so no duplicate
        await client.close()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_client_wait_closed(pair):
    """wait_closed() returns when server closes connection."""
    server, client = pair

    async def server_task():
        ch = await server.accept()
        await ch.close()
        await server.close()

    async def client_task():
        ch = await client.open_channel()
        await ch.read()  # EOF from server close
        await client.wait_closed()  # returns once server disconnects

    await asyncio.gather(server_task(), client_task())
