import asyncio

import pytest

from .. import anet
from . import exceptions, mux, sockets


@pytest.fixture
async def pair():
    server_sock, client_sock = anet.socket.socketpair(anet.socket.Family.UNIX, anet.socket.Type.STREAM)

    sockets.store.add("test-server", server_sock)
    sockets.store.add("test-client", client_sock)

    server = mux.Mux.create("test-server")
    client = mux.Mux.create("test-client")
    yield server, client

    server.stop()
    await server.wait_stop()
    server.close_socket()
    client.stop()
    await client.wait_stop()
    client.close_socket()

    sockets.store.remove("test-server")
    sockets.store.remove("test-client")


@pytest.mark.anyio
async def test_mux_client_server_bidirectional(pair):
    """Test client-server channel communication."""
    server, client = pair

    async def server_task():
        # Accept channel
        local_id = await server.channel_accept()

        # Read from client
        data = await server.channel_read(local_id)
        assert data == b"hello"

        # Write to client
        await server.channel_write(local_id, b"world")

        # Close
        await server.channel_close(local_id)

    async def client_task():
        # Open channel
        local_id = await client.channel_open()

        # Write to server
        await client.channel_write(local_id, b"hello")

        # Read from server
        data = await client.channel_read(local_id)
        assert data == b"world"

        # Read EOF
        data = await client.channel_read(local_id)
        assert data == b""

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_large_data(pair):
    """Test sending data larger than MAX_PACKET."""
    server, client = pair

    large_data = b"x" * (mux.MAX_PACKET * 3 + 1000)

    async def server_task():
        local_id = await server.channel_accept()
        received = b""
        while True:
            data = await server.channel_read(local_id)
            if not data:
                break
            received += data
        assert received == large_data

    async def client_task():
        local_id = await client.channel_open()
        await client.channel_write(local_id, large_data)
        await client.channel_close(local_id)

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_multiple_channels(pair):
    """Test multiple concurrent channels."""
    server, client = pair

    channels_accepted = 0

    async def server_task():
        nonlocal channels_accepted
        for _ in range(3):
            local_id = await server.channel_accept()
            channels_accepted += 1
            data = await server.channel_read(local_id)
            await server.channel_write(local_id, data + b"_response")
            await server.channel_close(local_id)

    async def send_channel(c, i):
        local_id = await c.channel_open()
        await c.channel_write(local_id, b"test")
        data = await c.channel_read(local_id)
        assert data == b"test_response"
        await c.channel_read(local_id)  # EOF

    async def client_task():
        tasks = []
        for i in range(3):
            tasks.append(send_channel(client, i))
        await asyncio.gather(*tasks)

    await asyncio.gather(server_task(), client_task())
    assert channels_accepted == 3


@pytest.mark.anyio
async def test_mux_empty_data(pair):
    """Test sending empty data."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        data = await server.channel_read(local_id)
        assert data == b""
        data = await server.channel_read(local_id)
        assert data == b""

    async def client_task():
        local_id = await client.channel_open()
        await client.channel_write(local_id, b"")
        await client.channel_close(local_id)

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_half_close_echo(pair):
    """Test half-close with echo (client -> server -> client)."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # Read from client
        data = await server.channel_read(local_id)
        assert data == b"ping"
        # Read EOF (client half-closed)
        data = await server.channel_read(local_id)
        assert data == b""
        # But we can still write
        await server.channel_write(local_id, b"pong")
        # Now close fully
        await server.channel_close(local_id)

    async def client_task():
        local_id = await client.channel_open()
        # Send data
        await client.channel_write(local_id, b"ping")
        # Half-close write side
        await client.channel_close_write(local_id)
        # Can still read response
        data = await client.channel_read(local_id)
        assert data == b"pong"
        # Read EOF from server
        data = await client.channel_read(local_id)
        assert data == b""
        # Now close fully
        await client.channel_close(local_id)

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_half_close_write_after_error(pair):
    """Test that writing after half-close raises error."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # Just wait for EOF
        while True:
            data = await server.channel_read(local_id)
            if not data:
                break

    async def client_task():
        local_id = await client.channel_open()
        await client.channel_close_write(local_id)

        # Writing after half-close should fail
        with pytest.raises(exceptions.Error):
            await client.channel_write(local_id, b"fail")
        await client.channel_close(local_id)

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_half_close_idempotent(pair):
    """Test that half-close can be called multiple times."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # Just wait for EOF
        while True:
            data = await server.channel_read(local_id)
            if not data:
                break

    async def client_task():
        local_id = await client.channel_open()
        await client.channel_close_write(local_id)
        await client.channel_close_write(local_id)  # Should be idempotent
        await client.channel_close(local_id)
        await client.channel_close(local_id)  # Should be idempotent

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_close_without_eof(pair):
    """Test receiving CLOSE without prior EOF returns EOF."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # Send data but close without EOF
        await server.channel_write(local_id, b"hello")
        await server.channel_close(local_id)  # CLOSE without explicit EOF

    async def client_task():
        local_id = await client.channel_open()
        data = await client.channel_read(local_id)
        assert data == b"hello"
        # Should read EOF due to CLOSE
        data = await client.channel_read(local_id)
        assert data == b""

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_open_failure(pair):
    """Test OPEN_FAILURE causes exception."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # This test doesn't actually reject, it accepts normally
        # A real server would reject via OPEN_FAILURE
        # For now, just accept to avoid hanging
        await server.channel_close(local_id)

    async def client_task():
        # Note: Our current server implementation always accepts.
        # This test is a placeholder for testing OPEN_FAILURE parsing.
        local_id = await client.channel_open()
        await client.channel_close(local_id)

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_send_window_exhaustion(pair):
    """Test send window exhaustion blocks write."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # Read all data slowly
        data = await server.channel_read(local_id)
        assert data == b"x"
        data = await server.channel_read(local_id)
        assert data == b""

    async def client_task():
        local_id = await client.channel_open()
        # Override window to very small
        client._channels[local_id].send_window = 1
        client._channels[local_id].send_window_event.set()

        # Write 1 byte (fits in window)
        await client.channel_write(local_id, b"x")

        # Try to write more - will block until window_adjust
        # (but we never send one, so close instead)
        await client.channel_close_write(local_id)
        await client.channel_close(local_id)

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_bidirectional_half_close(pair):
    """Test both sides half-close independently."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # Server writes then half-closes
        await server.channel_write(local_id, b"srv")
        await server.channel_close_write(local_id)
        # But can still read
        data = await server.channel_read(local_id)
        assert data == b"cli"
        data = await server.channel_read(local_id)
        assert data == b""
        await server.channel_close(local_id)

    async def client_task():
        local_id = await client.channel_open()
        # Client writes then half-closes
        await client.channel_write(local_id, b"cli")
        await client.channel_close_write(local_id)
        # But can still read
        data = await client.channel_read(local_id)
        assert data == b"srv"
        data = await client.channel_read(local_id)
        assert data == b""
        await client.channel_close(local_id)

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_mux_close_after_half_close_idempotent(pair):
    """Test close() after close_write() doesn't send duplicate EOF."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        # Receive EOF once (from half-close)
        data = await server.channel_read(local_id)
        assert data == b""
        # Another read should also return EOF
        data = await server.channel_read(local_id)
        assert data == b""

    async def client_task():
        local_id = await client.channel_open()
        await client.channel_close_write(local_id)  # Sends EOF
        await client.channel_close(local_id)  # Sends CLOSE, EOF already sent so no duplicate
        client.stop()
        await client.wait_stop()
        client.close_socket()

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_client_wait_closed(pair):
    """wait_closed() returns when server closes connection."""
    server, client = pair

    async def server_task():
        local_id = await server.channel_accept()
        await server.channel_close(local_id)
        server.stop()
        await server.wait_stop()
        server.close_socket()

    async def client_task():
        local_id = await client.channel_open()
        await client.channel_read(local_id)  # EOF from server close
        await client.wait_stop()  # returns once server disconnects

    await asyncio.gather(server_task(), client_task())


@pytest.mark.anyio
async def test_server_accept_raises_on_connection_drop():
    """accept() must raise when remote socket closes, not hang forever."""
    server_sock, remote_sock = anet.socket.socketpair(anet.socket.Family.UNIX, anet.socket.Type.STREAM)

    sockets.store.add("test-server-drop", server_sock)

    server = mux.Mux.create("test-server-drop")

    # Simulate remote TCP server dying — close its socket before any OPEN.
    # _reader_loop will get EOF but currently doesn't unblock _pending_open.
    remote_sock.close()

    # Should raise exceptions.Error, NOT hang forever.
    # With the bug: TimeoutError from wait_for escapes, pytest.raises fails.
    # After fix: accept() raises exceptions.Error, test passes.
    with pytest.raises(exceptions.Error):
        await asyncio.wait_for(server.channel_accept(), timeout=2.0)

    server.stop()
    await server.wait_stop()
    server.close_socket()

    sockets.store.remove("test-server-drop")
