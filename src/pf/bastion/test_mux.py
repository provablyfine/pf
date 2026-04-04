import asyncio
import base64
import uuid

import pytest

from . import _test_websocket, mux


@pytest.fixture
async def ws_pair():
    server_ws, client_ws = _test_websocket.create_websocket_pair()
    yield server_ws, client_ws
    await server_ws.close()
    await client_ws.close()


@pytest.fixture
async def server(ws_pair):
    server_ws, client_ws = ws_pair
    srv = mux.Server(server_ws)
    yield srv, client_ws
    await srv.close()


@pytest.mark.anyio
async def test_server_open_channel(server):
    srv, client = server
    channel = await srv.open_channel(meta={"name": "test-channel"})

    assert channel.channel_id is not None
    assert len(channel.channel_id) == 36

    open_msg = await client.receive_json()
    assert open_msg["type"] == "open"
    assert open_msg["channel_id"] == channel.channel_id
    assert "credits" in open_msg
    assert open_msg["meta"]["name"] == "test-channel"


@pytest.mark.anyio
async def test_server_open_channel_when_closed(ws_pair):
    server_ws, _ = ws_pair
    srv = mux.Server(server_ws)
    await srv.close()

    with pytest.raises(mux.MuxError):
        await srv.open_channel()


@pytest.mark.anyio
async def test_server_dispatch_data(server):
    srv, client = server
    channel = await srv.open_channel()

    open_msg = await client.receive_json()
    channel_id = open_msg["channel_id"]

    await client.send_json(
        {
            "type": "data",
            "channel_id": channel_id,
            "payload": "hello from client",
        }
    )

    received = await channel.receive()
    assert received == b"hello from client"


@pytest.mark.anyio
async def test_server_dispatch_ack(server):
    srv, client = server
    channel = await srv.open_channel()

    open_msg = await client.receive_json()
    channel_id = open_msg["channel_id"]

    for i in range(8):
        await client.send_json(
            {
                "type": "data",
                "channel_id": channel_id,
                "payload": f"test{i}",
            }
        )
        await channel.receive()

    ack_msg = await client.receive_json()
    assert ack_msg["type"] == "ack"
    assert ack_msg["channel_id"] == channel_id
    assert ack_msg["credits"] >= 1


@pytest.mark.anyio
async def test_server_dispatch_close(server):
    srv, client = server
    channel = await srv.open_channel()

    open_msg = await client.receive_json()
    channel_id = open_msg["channel_id"]

    await client.send_json(
        {
            "type": "close",
            "channel_id": channel_id,
        }
    )

    with pytest.raises(mux.ChannelError, match="closed by remote"):
        await channel.receive()


@pytest.mark.anyio
async def test_server_dispatch_unknown_channel(ws_pair):
    server_ws, client_ws = ws_pair
    srv = mux.Server(server_ws)

    await srv.open_channel()

    await client_ws.send_json(
        {
            "type": "data",
            "channel_id": str(uuid.uuid4()),
            "payload": "unknown",
        }
    )

    await asyncio.sleep(0.1)


@pytest.mark.anyio
async def test_server_channel_send(server):
    srv, client = server
    channel = await srv.open_channel()

    open_msg = await client.receive_json()
    channel_id = open_msg["channel_id"]

    await channel.send(b"hello from server")

    data_msg = await client.receive_json()
    assert data_msg["type"] == "data"
    assert data_msg["channel_id"] == channel_id
    assert data_msg["payload"] == "aGVsbG8gZnJvbSBzZXJ2ZXI="


@pytest.mark.anyio
async def test_server_channel_send_blocks_on_credit(ws_pair):
    server_ws, client_ws = ws_pair
    srv = mux.Server(server_ws, initial_tx_credits=2)

    channel = await srv.open_channel()

    await client_ws.receive_json()

    await channel.send(b"msg1")
    await channel.send(b"msg2")

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(channel.send(b"msg3"), timeout=0.5)

    await srv.close()


@pytest.mark.anyio
async def test_server_fail_on_disconnect(ws_pair):
    server_ws, client_ws = ws_pair
    srv = mux.Server(server_ws)

    channel = await srv.open_channel()

    await client_ws.receive_json()

    await client_ws.close()

    await asyncio.sleep(0.1)

    with pytest.raises(mux.ChannelError, match="connection lost"):
        await channel.receive()


@pytest.mark.anyio
async def test_server_channel_close(server):
    srv, client = server
    channel = await srv.open_channel()

    open_msg = await client.receive_json()
    channel_id = open_msg["channel_id"]

    await channel.close()

    close_msg = await client.receive_json()
    assert close_msg["type"] == "close"
    assert close_msg["channel_id"] == channel_id

    with pytest.raises(mux.ChannelError, match="already closed"):
        await channel.send(b"after close")


@pytest.mark.anyio
async def test_server_channel_close_idempotent(server):
    srv, client = server
    channel = await srv.open_channel()

    await client.receive_json()

    await channel.close()
    await channel.close()


@pytest.mark.anyio
async def test_integration_full_cycle(server):
    srv, client = server
    channel = await srv.open_channel(meta={"role": "test"})

    open_msg = await client.receive_json()
    channel_id = open_msg["channel_id"]
    initial_credit = open_msg["credits"]

    assert initial_credit == 16

    for i in range(8):
        await client.send_json(
            {
                "type": "data",
                "channel_id": channel_id,
                "payload": f"client message {i}",
            }
        )

    for i in range(8):
        msg = await channel.receive()
        assert msg == f"client message {i}".encode()

    ack = await client.receive_json()
    assert ack["type"] == "ack"

    await channel.send(b"server response")

    resp = await client.receive_json()
    assert resp["type"] == "data"
    assert base64.b64decode(resp["payload"]).decode() == "server response"

    await channel.close()

    close_msg = await client.receive_json()
    assert close_msg["type"] == "close"
