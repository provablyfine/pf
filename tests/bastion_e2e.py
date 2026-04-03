import asyncio
import copy
import os
import random
import subprocess
import tempfile
import time
from collections.abc import Sequence
from typing import cast

import pytest
import websockets
import websockets.client
import websockets.typing

from pf.bastion import demux


@pytest.fixture
def bastion(request):
    tmp_dir = tempfile.TemporaryDirectory()
    port_file = os.path.join(tmp_dir.name, "bastion.port")
    log_file = os.path.join(tmp_dir.name, "bastion.log")

    env = copy.copy(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env.pop("HTTP_PROXY", None)
    env.pop("http_proxy", None)
    env.pop("HTTPS_PROXY", None)
    env.pop("https_proxy", None)
    env.pop("NO_PROXY", None)
    env.pop("no_proxy", None)
    src_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    env["PYTHONPATH"] = src_path
    log_f = open(log_file, "w+")
    venv_python = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".venv", "bin", "python3")
    run_code = "from pf.bastion.server import run; import sys; "
    run_code += "sys.argv = ['server', '--dev', '--port-file', '"
    run_code += port_file + "']; run()"
    popen = subprocess.Popen(
        [venv_python, "-c", run_code],
        stdout=log_f,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    print(f"Started bastion server with PID {popen.pid}, port_file: {port_file}")

    start = time.time()
    port: int | None = None
    while time.time() - start < 5:
        try:
            with open(port_file) as f:
                data = f.read()
                print(f"Port file content: {data!r}")
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        try:
            port = int(data.strip())
            print(f"Parsed port: {port}")
        except Exception as e:
            print(f"Parse error: {e}")
            time.sleep(0.1)
            continue
        break

    if port is None:
        # Print the log to see what went wrong
        log_f.flush()
        with open(log_file) as f:
            print(f"Bastion log: {f.read()}")
        raise Exception("Unable to start bastion server")

    yield port

    popen.terminate()
    popen.wait()
    log_f.close()
    with open(log_file) as f:
        log_content = f.read()
    if hasattr(request.node, "rep_call"):
        if request.node.rep_call.failed:
            print(f"Bastion log:\n{log_content}")
            print(f"Bastion port: {port}")
            return
    tmp_dir.cleanup()


@pytest.mark.anyio
async def test_bastion_100k_transfer(bastion):
    """
    E2E test: register a host, then connect and send 100K.

    This verifies the WebSocket connection and mux channel setup work correctly.
    """
    port = bastion
    data_to_send = random.randbytes(100 * 1024)
    subprotocol_mux = cast(Sequence[websockets.typing.Subprotocol], ("mux-ssh",))
    subprotocol_ssh = cast(Sequence[websockets.typing.Subprotocol], ("ssh",))

    async def host():
        print("host: connecting to /register", flush=True)
        uri = f"ws://127.0.0.1:{port}/register"
        async with websockets.connect(uri, subprotocols=subprotocol_mux):
            print("host: connected, waiting...", flush=True)
            await asyncio.sleep(10)
            print("host: done waiting", flush=True)

    async def client():
        await asyncio.sleep(0.5)
        print("client: connecting to /connect", flush=True)
        uri = f"ws://127.0.0.1:{port}/connect?hostname=hello"
        async with websockets.connect(uri, subprotocols=subprotocol_ssh) as ws:
            print("client: connected, sending data...", flush=True)
            await ws.send(data_to_send)
            print("client: sent data", flush=True)

    await asyncio.gather(host(), client())


@pytest.mark.anyio
async def test_host_reads_client_data(bastion):
    """
    E2E test: client sends data through the bastion, host reads it via the mux protocol.

    The host speaks the mux client-side protocol over the /register WebSocket:
    it waits for an "open" frame, reads "data" frames (base64 payload), sends
    "ack" frames to replenish flow-control credits, and stops on "close".
    """
    port = bastion
    data_to_send = random.randbytes(50 * 1024)
    subprotocol_mux = cast(Sequence[websockets.typing.Subprotocol], ("mux-ssh",))
    subprotocol_ssh = cast(Sequence[websockets.typing.Subprotocol], ("ssh",))

    received_chunks: list[bytes] = []

    async def host():
        uri = f"ws://127.0.0.1:{port}/register"
        async with websockets.connect(uri, subprotocols=subprotocol_mux) as ws:
            mux_client = demux.Client(ws)
            ch = await mux_client.accept_channel()
            try:
                while True:
                    received_chunks.append(await ch.receive())
            except demux.ChannelError:
                pass

    async def client():
        await asyncio.sleep(0.5)
        uri = f"ws://127.0.0.1:{port}/connect?hostname=hello"
        async with websockets.connect(uri, subprotocols=subprotocol_ssh) as ws:
            await ws.send(data_to_send)

    await asyncio.gather(host(), client())

    assert b"".join(received_chunks) == data_to_send


@pytest.mark.anyio
async def test_host_reads_two_concurrent_clients(bastion):
    """
    E2E test: two clients send data concurrently; host reads both streams correctly.

    The server opens a separate mux channel for each client. The host dispatches
    inbound frames by channel_id, accumulating data per channel, and sends acks
    to keep flow control healthy. The test verifies that neither stream is lost
    or mixed up.
    """
    port = bastion
    data1 = random.randbytes(20 * 1024)
    data2 = random.randbytes(20 * 1024)
    subprotocol_mux = cast(Sequence[websockets.typing.Subprotocol], ("mux-ssh",))
    subprotocol_ssh = cast(Sequence[websockets.typing.Subprotocol], ("ssh",))

    # channel_id -> list of received chunks
    received: dict[str, list[bytes]] = {}

    async def host():
        uri = f"ws://127.0.0.1:{port}/register"
        async with websockets.connect(uri, subprotocols=subprotocol_mux) as ws:
            mux_client = demux.Client(ws)

            async def drain(ch: demux.Channel) -> None:
                received[ch.channel_id] = []
                try:
                    while True:
                        received[ch.channel_id].append(await ch.receive())
                except demux.ChannelError:
                    pass

            channels = [await mux_client.accept_channel() for _ in range(2)]
            await asyncio.gather(*[drain(ch) for ch in channels])

    async def client(data: bytes):
        await asyncio.sleep(0.5)
        uri = f"ws://127.0.0.1:{port}/connect?hostname=hello"
        async with websockets.connect(uri, subprotocols=subprotocol_ssh) as ws:
            await ws.send(data)

    await asyncio.gather(host(), client(data1), client(data2))

    assert len(received) == 2
    received_payloads = {b"".join(chunks) for chunks in received.values()}
    assert received_payloads == {data1, data2}


@pytest.mark.anyio
async def test_host_echoes_data_to_clients(bastion):
    """
    E2E test: host echoes each client's data back; clients verify what they receive.

    Two clients connect concurrently, each sending a unique payload. The host
    reads each data frame and sends it straight back on the same channel. Each
    client asserts that the bytes it receives match what it originally sent.

    This exercises the full bidirectional relay: client→server→host (via mux
    data frames) and host→server→client (via mux data frames back through the
    channel-to-ws relay).
    """
    port = bastion
    data1 = random.randbytes(10 * 1024)
    data2 = random.randbytes(10 * 1024)
    subprotocol_mux = cast(Sequence[websockets.typing.Subprotocol], ("mux-ssh",))
    subprotocol_ssh = cast(Sequence[websockets.typing.Subprotocol], ("ssh",))

    async def host():
        uri = f"ws://127.0.0.1:{port}/register"
        async with websockets.connect(uri, subprotocols=subprotocol_mux) as ws:
            mux_client = demux.Client(ws)

            async def echo(ch: demux.Channel) -> None:
                try:
                    while True:
                        await ch.send(await ch.receive())
                except demux.ChannelError:
                    pass

            channels = [await mux_client.accept_channel() for _ in range(2)]
            await asyncio.gather(*[echo(ch) for ch in channels])

    async def client(data: bytes) -> bytes:
        await asyncio.sleep(0.5)
        uri = f"ws://127.0.0.1:{port}/connect?hostname=hello"
        async with websockets.connect(uri, subprotocols=subprotocol_ssh) as ws:
            await ws.send(data)
            return cast(bytes, await ws.recv())

    _, echo1, echo2 = await asyncio.gather(host(), client(data1), client(data2))

    assert echo1 == data1
    assert echo2 == data2
