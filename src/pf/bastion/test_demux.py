"""
Tests for demux.Client (h2 server side).

Tests create a connected (mux.Server, demux.Client) pair and verify the
client-side behaviour: accepting channels, sending/receiving data, close
semantics, and error handling.
"""

import asyncio

import pytest

from . import _test_websocket, demux, mux


@pytest.fixture
async def pair():
    server_ws, client_ws = await _test_websocket.create_ws_pair()
    srv = mux.Server(server_ws)
    cli = demux.Client(client_ws)
    yield srv, cli
    await cli.close()
    await srv.close()


# ---------------------------------------------------------------------------
# Channel acceptance
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_client_accept_channel(pair):
    srv, cli = pair
    await srv.open_channel(meta={"role": "test"})
    ch = await cli.accept_channel()
    assert ch.meta == {"role": "test"}
    assert ch.channel_id is not None


@pytest.mark.anyio
async def test_client_accept_channel_empty_meta(pair):
    srv, cli = pair
    await srv.open_channel()
    ch = await cli.accept_channel()
    assert ch.meta == {}


# ---------------------------------------------------------------------------
# Data transfer
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_client_channel_receive(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await srv_ch.send(b"hello from server")
    data = await cli_ch.receive()
    assert data == b"hello from server"


@pytest.mark.anyio
async def test_client_channel_send(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await cli_ch.send(b"hello from client")
    data = await srv_ch.receive()
    assert data == b"hello from client"


# ---------------------------------------------------------------------------
# Channel close
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_client_channel_close_by_server(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await srv_ch.close()

    with pytest.raises(demux.ChannelError, match="closed by remote"):
        await cli_ch.receive()


@pytest.mark.anyio
async def test_client_channel_close_by_client(pair):
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    await cli_ch.close()

    with pytest.raises(mux.ChannelError, match="closed by remote"):
        await srv_ch.receive()


# ---------------------------------------------------------------------------
# Disconnection
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_client_fail_on_disconnect(pair):
    srv, cli = pair
    await srv.close()
    await asyncio.sleep(0.1)

    with pytest.raises(demux.MuxError):
        await cli.accept_channel()


# ---------------------------------------------------------------------------
# Flow control (h2 window)
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_large_payload(pair):
    """Send a payload larger than the default h2 window (65535 bytes)."""
    srv, cli = pair
    srv_ch = await srv.open_channel()
    cli_ch = await cli.accept_channel()

    # 128 KB — larger than the default 64 KB flow control window.
    large = b"x" * (128 * 1024)
    send_task = asyncio.create_task(srv_ch.send(large))

    received = b""
    while len(received) < len(large):
        chunk = await asyncio.wait_for(cli_ch.receive(), timeout=5.0)
        received += chunk

    await send_task
    assert received == large
