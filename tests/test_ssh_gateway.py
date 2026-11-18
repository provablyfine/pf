"""Integration tests for the browser to bastion websocket gateway."""

import asyncio
import contextlib
import json
import socket
import struct

import pytest

import provablyfine.bastion_visitor

from . import test_identity_self_token as base

websockets_client = pytest.importorskip("websockets.asyncio.client")
websockets_exceptions = pytest.importorskip("websockets.exceptions")

TENANT_UUID = "00000000-0000-0000-0000-000000000001"


@contextlib.asynccontextmanager
async def _fake_bastion():
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\n\r\n")
        header = await reader.readexactly(9)
        await reader.readexactly(struct.unpack(">Q", header[1:])[0])
        writer.write(provablyfine.bastion_visitor.encode_frame(provablyfine.bastion_visitor.ACCEPT_TAG, {"ok": True}))
        await writer.drain()
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _signed_in(api, tmp_path):
    factory, identity_name, role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    base._grant_shell(sc, role_id, identity_name, max_session_ttl_s=3600)
    return sc, identity_name


def _register_bastion(sc, port: int, tag_id_list: list[int] | None = None) -> int:
    return sc.create_bastion(
        url=f"http://127.0.0.1:{port}", ssh_proxy_jump=None, tag_id_list=tag_id_list, tag_name_value_list=[]
    ).id


def _connect_token(sc, host: str) -> str:
    connection_id = base._sign_cert(sc, host)
    return sc.get_self_token("bastion", hostname=host, purpose="connect", connection_id=connection_id).token


def _url(api) -> str:
    return f"ws://127.0.0.1:{api.port}/pf/t/{TENANT_UUID}/ssh/gateway/ws"


def _hello(token: str, bastion_id: int) -> str:
    return json.dumps({"token": token, "bastion_id": bastion_id})


async def _close_code(ws) -> int:
    with pytest.raises(websockets_exceptions.ConnectionClosed) as info:
        await asyncio.wait_for(ws.recv(), 10)
    assert info.value.rcvd is not None
    return info.value.rcvd.code


async def _echo(ws, payload: bytes = b"ping") -> None:
    await ws.send(payload)
    assert await asyncio.wait_for(ws.recv(), 10) == payload


def test_the_gateway_forwards_bytes_to_the_bastion_and_back(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)

    async def scenario():
        async with _fake_bastion() as port:
            bastion_id = _register_bastion(sc, port)
            async with websockets_client.connect(_url(api)) as ws:
                await ws.send(_hello(_connect_token(sc, host), bastion_id))
                await _echo(ws, b"hello")
                await _echo(ws, bytes(range(256)) * 200)

    asyncio.run(scenario())


def test_a_garbage_token_is_refused(api, tmp_path):
    sc, _host = _signed_in(api, tmp_path)

    async def scenario():
        async with _fake_bastion() as port:
            bastion_id = _register_bastion(sc, port)
            async with websockets_client.connect(_url(api)) as ws:
                await ws.send(_hello("not-a-token", bastion_id))
                assert await _close_code(ws) == 4401

    asyncio.run(scenario())


def test_a_register_token_is_refused(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)

    async def scenario():
        async with _fake_bastion() as port:
            bastion_id = _register_bastion(sc, port)
            token = sc.get_self_token("bastion", hostname=host, purpose="register").token
            async with websockets_client.connect(_url(api)) as ws:
                await ws.send(_hello(token, bastion_id))
                assert await _close_code(ws) == 4401

    asyncio.run(scenario())


def test_an_unknown_bastion_id_is_refused(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)

    async def scenario():
        async with websockets_client.connect(_url(api)) as ws:
            await ws.send(_hello(_connect_token(sc, host), 999_999))
            assert await _close_code(ws) == 4401

    asyncio.run(scenario())


def test_a_bastion_the_identity_cannot_see_is_refused(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)
    tag = sc.create_tag("zone", "private")

    async def scenario():
        async with _fake_bastion() as port:
            hidden_bastion_id = _register_bastion(sc, port, tag_id_list=[tag.id])
            async with websockets_client.connect(_url(api)) as ws:
                await ws.send(_hello(_connect_token(sc, host), hidden_bastion_id))
                assert await _close_code(ws) == 4401

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "first",
    [
        "not json",
        "[]",
        "{}",
        '{"token": "x"}',
        '{"bastion_id": 1}',
        '{"token": 1, "bastion_id": 1}',
        '{"token": "x", "bastion_id": "1"}',
        '{"token": "x", "bastion_id": true}',
        '{"token": "' + "x" * 9000 + '", "bastion_id": 1}',
        b"\x00\x01\x02",
    ],
    ids=lambda first: "binary" if isinstance(first, bytes) else first[:30],
)
def test_a_malformed_first_message_is_refused(api, first):
    async def scenario():
        async with websockets_client.connect(_url(api)) as ws:
            await ws.send(first)
            assert await _close_code(ws) == 4401

    asyncio.run(scenario())


def test_an_unknown_tenant_is_refused_cleanly(api):
    async def scenario():
        url = f"ws://127.0.0.1:{api.port}/pf/t/99999999-9999-9999-9999-999999999999/ssh/gateway/ws"
        async with websockets_client.connect(url) as ws:
            await ws.send(_hello("x", 1))
            assert await _close_code(ws) == 4401

    asyncio.run(scenario())


def test_an_unreachable_bastion_is_reported(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)
    bastion_id = _register_bastion(sc, _closed_port())

    async def scenario():
        async with websockets_client.connect(_url(api)) as ws:
            await ws.send(_hello(_connect_token(sc, host), bastion_id))
            assert await _close_code(ws) == 4502

    asyncio.run(scenario())


@pytest.mark.parametrize("api", [{"gateway_allowed_origins": ["https://app.example"]}], indirect=True)
def test_an_origin_outside_the_allow_list_is_rejected_at_the_handshake(api):
    async def scenario():
        with pytest.raises(websockets_exceptions.InvalidStatus) as info:
            async with websockets_client.connect(_url(api), origin="https://evil.example"):
                pass
        assert info.value.response.status_code == 403

    asyncio.run(scenario())


@pytest.mark.parametrize("api", [{"gateway_allowed_origins": ["https://app.example"]}], indirect=True)
def test_an_origin_on_the_allow_list_is_accepted(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)

    async def scenario():
        async with _fake_bastion() as port:
            bastion_id = _register_bastion(sc, port)
            async with websockets_client.connect(_url(api), origin="https://app.example") as ws:
                await ws.send(_hello(_connect_token(sc, host), bastion_id))
                await _echo(ws)

    asyncio.run(scenario())


@pytest.mark.parametrize("api", [{"gateway_max_sessions_per_identity": 2}], indirect=True)
def test_an_identity_cannot_exceed_its_session_limit(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)

    async def scenario():
        async with _fake_bastion() as port, contextlib.AsyncExitStack() as stack:
            bastion_id = _register_bastion(sc, port)
            for _ in range(2):
                ws = await stack.enter_async_context(websockets_client.connect(_url(api)))
                await ws.send(_hello(_connect_token(sc, host), bastion_id))
                await _echo(ws)
            async with websockets_client.connect(_url(api)) as third:
                await third.send(_hello(_connect_token(sc, host), bastion_id))
                assert await _close_code(third) == 4429

    asyncio.run(scenario())


@pytest.mark.parametrize("api", [{"gateway_idle_timeout": 1}], indirect=True)
def test_an_idle_session_is_closed(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)

    async def scenario():
        async with _fake_bastion() as port:
            bastion_id = _register_bastion(sc, port)
            async with websockets_client.connect(_url(api)) as ws:
                await ws.send(_hello(_connect_token(sc, host), bastion_id))
                await _echo(ws)
                assert await _close_code(ws) == 1000

    asyncio.run(scenario())


@pytest.mark.parametrize("api", [{"gateway_idle_timeout": 1}], indirect=True)
def test_a_session_with_traffic_stays_open(api, tmp_path):
    sc, host = _signed_in(api, tmp_path)

    async def scenario():
        async with _fake_bastion() as port:
            bastion_id = _register_bastion(sc, port)
            async with websockets_client.connect(_url(api)) as ws:
                await ws.send(_hello(_connect_token(sc, host), bastion_id))
                for _ in range(5):
                    await _echo(ws)
                    await asyncio.sleep(0.5)

    asyncio.run(scenario())


@pytest.mark.parametrize("api", [{"gateway_max_unauthenticated_sockets": 2}], indirect=True)
def test_unauthenticated_sockets_are_capped(api):
    async def scenario():
        async with contextlib.AsyncExitStack() as stack:
            for _ in range(2):
                await stack.enter_async_context(websockets_client.connect(_url(api)))
            with pytest.raises(websockets_exceptions.InvalidStatus) as info:
                async with websockets_client.connect(_url(api)):
                    pass
            assert info.value.response.status_code == 403
        async with websockets_client.connect(_url(api)) as ws:
            await ws.send("not json")
            assert await _close_code(ws) == 4401

    asyncio.run(scenario())
