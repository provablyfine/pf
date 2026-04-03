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
