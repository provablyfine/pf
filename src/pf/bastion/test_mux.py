"""
Tests for mux.Server (h2 client side).

Tests create a connected (mux.Server, mux.Client) pair and verify the
server-side behaviour: opening channels, sending/receiving data, close
semantics, and error handling.
"""

import asyncio

import pytest

from . import _test_websocket, mux


@pytest.fixture
async def pair():
    server_ws, client_ws = await _test_websocket.create_ws_pair()
    srv = mux.Server(server_ws)
    cli = mux.Client(client_ws)
    yield srv, cli
    await srv.close()
    await cli.close()


# ---------------------------------------------------------------------------
# Channel opening
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_server_open_channel(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    await cli.accept_channel()

    assert srv_ch.channel_id is not None


@pytest.mark.anyio
async def test_server_open_channel_when_closed(pair):
    srv, _cli = pair
    await srv.close()

    with pytest.raises(mux.MuxError):
        await srv.open_channel()


@pytest.mark.anyio
async def test_server_open_channel_empty_meta(pair):
    srv, cli = pair
    await srv.open_channel()
    cli_ch = await cli.accept_channel()
    assert cli_ch.channel_id is not None


# ---------------------------------------------------------------------------
# Data transfer
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_server_sends_data_to_client(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await srv_ch.send(b"hello from server")
    data = await cli_ch.receive()
    assert data == b"hello from server"


@pytest.mark.anyio
async def test_client_sends_data_to_server(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await cli_ch.send(b"hello from client")
    data = await srv_ch.receive()
    assert data == b"hello from client"


@pytest.mark.anyio
async def test_bidirectional_data(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await srv_ch.send(b"ping")
    assert await cli_ch.receive() == b"ping"

    await cli_ch.send(b"pong")
    assert await srv_ch.receive() == b"pong"


@pytest.mark.anyio
async def test_binary_data(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    payload = bytes(range(256))
    await srv_ch.send(payload)
    assert await cli_ch.receive() == payload


# ---------------------------------------------------------------------------
# Channel close
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_server_closes_channel(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await srv_ch.close()

    with pytest.raises(mux.ChannelError, match="closed by remote"):
        await cli_ch.receive()


@pytest.mark.anyio
async def test_client_closes_channel(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await cli_ch.close()

    with pytest.raises(mux.ChannelError, match="closed by remote"):
        await srv_ch.receive()


@pytest.mark.anyio
async def test_server_close_raises_on_subsequent_send(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    await cli.accept_channel()

    await srv_ch.close()

    with pytest.raises(mux.ChannelError, match="already closed"):
        await srv_ch.send(b"after close")


@pytest.mark.anyio
async def test_server_close_idempotent(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    await cli.accept_channel()

    await srv_ch.close()
    await srv_ch.close()  # second close is a no-op


# ---------------------------------------------------------------------------
# Multiple channels
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_multiple_channels(pair):
    srv, cli = pair
    ch1 = await srv.open_channel()
    ch2 = await srv.open_channel()

    cli_ch1 = await cli.accept_channel()
    cli_ch2 = await cli.accept_channel()

    await ch1.send(b"ch1 data")
    await ch2.send(b"ch2 data")

    assert await cli_ch1.receive() == b"ch1 data"
    assert await cli_ch2.receive() == b"ch2 data"


# ---------------------------------------------------------------------------
# Disconnection
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_server_fail_on_disconnect(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    await cli.accept_channel()

    await cli.close()
    await asyncio.sleep(0.1)

    with pytest.raises(mux.ChannelError, match="connection lost"):
        await srv_ch.receive()


# ---------------------------------------------------------------------------
# Integration
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_integration_full_cycle(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    for i in range(8):
        await cli_ch.send(f"client message {i}".encode())

    for i in range(8):
        msg = await srv_ch.receive()
        assert msg == f"client message {i}".encode()

    await srv_ch.send(b"server response")
    assert await cli_ch.receive() == b"server response"

    await srv_ch.close()
    with pytest.raises(mux.ChannelError, match="closed by remote"):
        await cli_ch.receive()
