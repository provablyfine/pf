import asyncio
import base64

import pytest

from . import demux
from ._test_websocket import create_demux_pair


@pytest.fixture
async def pair():
    server, client_ws = create_demux_pair()
    client = demux.Client(client_ws)
    yield server, client
    await client.close()
    await server.close()


def _open_frame(channel_id: str, credits: int = 16, ack_threshold: int = 8, meta: dict | None = None) -> dict:
    return {
        "type": "open",
        "channel_id": channel_id,
        "meta": meta or {},
        "credits": credits,
        "ack_threshold": ack_threshold,
    }


def _data_frame(channel_id: str, payload: bytes) -> dict:
    return {
        "type": "data",
        "channel_id": channel_id,
        "payload": base64.b64encode(payload).decode("ascii"),
    }


def _close_frame(channel_id: str) -> dict:
    return {"type": "close", "channel_id": channel_id}


def _ack_frame(channel_id: str, credits: int) -> dict:
    return {"type": "ack", "channel_id": channel_id, "credits": credits}


@pytest.mark.anyio
async def test_client_accept_channel(pair):
    server, client = pair
    channel_id = "test-channel-1"
    await server.send_json(_open_frame(channel_id, meta={"role": "test"}))

    ch = await client.accept_channel()
    assert ch.channel_id == channel_id
    assert ch.meta == {"role": "test"}


@pytest.mark.anyio
async def test_client_channel_receive(pair):
    server, client = pair
    channel_id = "ch-recv"
    await server.send_json(_open_frame(channel_id))
    ch = await client.accept_channel()

    await server.send_json(_data_frame(channel_id, b"hello from server"))
    data = await ch.receive()
    assert data == b"hello from server"


@pytest.mark.anyio
async def test_client_channel_send(pair):
    server, client = pair
    channel_id = "ch-send"
    await server.send_json(_open_frame(channel_id))
    ch = await client.accept_channel()

    await ch.send(b"hello from client")

    msg = await server.receive_json()
    assert msg["type"] == "data"
    assert msg["channel_id"] == channel_id
    assert base64.b64decode(msg["payload"]) == b"hello from client"


@pytest.mark.anyio
async def test_client_sends_ack_after_threshold(pair):
    server, client = pair
    channel_id = "ch-ack"
    ack_threshold = 4
    await server.send_json(_open_frame(channel_id, ack_threshold=ack_threshold))
    ch = await client.accept_channel()

    for i in range(ack_threshold):
        await server.send_json(_data_frame(channel_id, f"msg{i}".encode()))
        await ch.receive()

    ack = await server.receive_json()
    assert ack["type"] == "ack"
    assert ack["channel_id"] == channel_id
    assert ack["credits"] >= 1


@pytest.mark.anyio
async def test_client_channel_close_by_server(pair):
    server, client = pair
    channel_id = "ch-close-server"
    await server.send_json(_open_frame(channel_id))
    ch = await client.accept_channel()

    await server.send_json(_close_frame(channel_id))

    with pytest.raises(demux.ChannelError, match="closed by remote"):
        await ch.receive()


@pytest.mark.anyio
async def test_client_channel_close_by_client(pair):
    server, client = pair
    channel_id = "ch-close-client"
    await server.send_json(_open_frame(channel_id))
    ch = await client.accept_channel()

    await ch.close()

    msg = await server.receive_json()
    assert msg["type"] == "close"
    assert msg["channel_id"] == channel_id


@pytest.mark.anyio
async def test_client_replenishes_tx_credits_on_ack(pair):
    server, client = pair
    channel_id = "ch-credits"
    await server.send_json(_open_frame(channel_id, credits=1))
    ch = await client.accept_channel()

    await ch.send(b"first")
    await server.receive_json()  # consume the data frame

    # No credits left — send should block.
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(ch.send(b"blocked"), timeout=0.2)

    # Server sends ack to replenish credits.
    await server.send_json(_ack_frame(channel_id, 1))

    # Now send should complete.
    await asyncio.wait_for(ch.send(b"after ack"), timeout=1.0)
    msg = await server.receive_json()
    assert base64.b64decode(msg["payload"]) == b"after ack"


@pytest.mark.anyio
async def test_client_fail_on_disconnect(pair):
    server, client = pair
    await server.close()

    with pytest.raises(demux.MuxError):
        await client.accept_channel()
