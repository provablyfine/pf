from __future__ import annotations

import argparse
import asyncio
import base64
import functools
import http.client
import importlib.resources
import json
import logging
import os
import pathlib
import shutil
import signal
import socket
import ssl
import stat
import sys
import tempfile
import urllib.parse

import provablyfine_client as pfc

from ... import client
from .. import http as cli_http
from .. import login

logger = logging.getLogger(__name__)

_FRPC_TOKEN_REFRESH_INTERVAL = 45


def _jwt_audience(token: str) -> str:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return str(claims["aud"])


def _frpc_binary() -> str:
    frpc_resource = importlib.resources.files("provablyfine").joinpath("bin/frpc")
    frpc_path = pathlib.Path(str(frpc_resource))
    if frpc_path.is_file():
        mode = frpc_path.stat().st_mode
        if not (mode & stat.S_IXUSR):
            try:
                frpc_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                pass
        if os.access(frpc_path, os.X_OK):
            return str(frpc_path)
    frpc_in_path = shutil.which("frpc")
    if frpc_in_path:
        return frpc_in_path
    raise pfc.exceptions.UI("frpc not found: reinstall provablyfine or install frpc manually")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_frpc_config(
    path: str,
    server_addr: str,
    user: str,
    jwt_token: str,
    web_port: int,
    local_port: int,
    bastion_domain: str,
) -> None:
    content = f"""serverAddr = "{server_addr}"
serverPort = 443
user = "{user}"

[auth]
method = "token"
token = ""

[transport]
protocol = "wss"

[metadatas]
jwt = "{jwt_token}"

[webServer]
addr = "127.0.0.1"
port = {web_port}

[[proxies]]
name = "ssh"
type = "tcpMuxHTTPConnect"
localIP = "127.0.0.1"
localPort = {local_port}
customDomains = ["{user}.{bastion_domain}"]
"""
    with open(path, "w") as f:
        f.write(content)


def _reload_frpc(web_port: int) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", web_port, timeout=5)
    try:
        conn.request("POST", "/api/reload")
        conn.getresponse()
    except Exception as e:
        logger.warning(f"frpc reload failed: {e}")
    finally:
        conn.close()


async def _manage_frpc(
    sc: pfc.AsyncSessionClient,
    bastion_url: str,
    identity_name: str,
    local_port: int,
    stop_event: asyncio.Event,
) -> None:
    u = urllib.parse.urlsplit(bastion_url)
    server_addr = u.hostname or bastion_url
    # server_addr is the frps control host (e.g. frps.bastion.provablyfine.net).
    # bastion_domain is what SSH clients target (e.g. bastion.provablyfine.net),
    # derived by stripping the first DNS label.
    parts = server_addr.split(".", 1)
    bastion_domain = parts[1] if len(parts) > 1 else server_addr

    config_fd, config_path = tempfile.mkstemp(suffix=".toml", prefix="frpc-")
    os.close(config_fd)

    try:
        while not stop_event.is_set():
            token_response = await sc.get_self_token("bastion", hostname=identity_name)
            frpc_user = _jwt_audience(token_response.token)
            web_port = _find_free_port()
            _write_frpc_config(
                config_path,
                server_addr,
                frpc_user,
                token_response.token,
                web_port,
                local_port,
                bastion_domain,
            )

            process = await asyncio.create_subprocess_exec(_frpc_binary(), "-c", config_path)
            logger.info(f"frpc started for bastion={bastion_url} identity={identity_name}")

            try:
                while not stop_event.is_set():
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=_FRPC_TOKEN_REFRESH_INTERVAL)
                        break
                    except TimeoutError:
                        pass

                    if process.returncode is not None:
                        break

                    token_response = await sc.get_self_token("bastion", hostname=identity_name)
                    _write_frpc_config(
                        config_path,
                        server_addr,
                        frpc_user,
                        token_response.token,
                        web_port,
                        local_port,
                        bastion_domain,
                    )
                    await asyncio.to_thread(_reload_frpc, web_port)
                    logger.debug(f"frpc token refreshed for bastion={bastion_url}")
            finally:
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except TimeoutError:
                        process.kill()
                        await process.wait()

            if not stop_event.is_set():
                logger.info(f"frpc exited, restarting in 5s for bastion={bastion_url}")
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=5)
                except TimeoutError:
                    pass
    finally:
        try:
            os.unlink(config_path)
        except OSError:
            pass


@client.ssh_utils.exception
def _register_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    factory = client.Factory(c, timeout=args.timeout)
    login.ensure_session(c, factory)

    async def _run() -> None:
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def signal_handler() -> None:
            stop_event.set()

        loop.add_signal_handler(signal.SIGTERM, signal_handler)
        loop.add_signal_handler(signal.SIGINT, signal_handler)

        sc = client.Factory(c, timeout=args.timeout).async_session()
        identity = await sc.get_self()
        identity_name = identity.name

        active_tasks: dict[int, asyncio.Task[None]] = {}

        def done_callback(bastion_id: int, task: asyncio.Task[None]) -> None:
            active_tasks.pop(bastion_id, None)

        while not stop_event.is_set():
            try:
                bastions_response = await sc.list_self_bastions()
                current_bastions = {b.id: b for b in bastions_response.bastions}

                for bastion_id in list(active_tasks.keys()):
                    if bastion_id not in current_bastions:
                        task = active_tasks.pop(bastion_id)
                        task.cancel()

                for bastion_id, bastion in current_bastions.items():
                    if bastion_id in active_tasks:
                        continue
                    task = asyncio.create_task(_manage_frpc(sc, bastion.url, identity_name, args.port, stop_event))
                    active_tasks[bastion_id] = task
                    task.add_done_callback(functools.partial(done_callback, bastion_id))
            except Exception as e:
                logger.debug(f"Poll error: {e}")

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=args.poll_interval)
            except TimeoutError:
                pass

        for task in list(active_tasks.values()):
            task.cancel()
        if active_tasks:
            await asyncio.gather(*active_tasks.values(), return_exceptions=True)

    asyncio.run(_run())


async def connect_async(url: str, hostname: str) -> None:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or url
    scheme_port = 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
    port = u.port if u.port is not None else scheme_port

    if u.scheme not in ["http", "https"]:
        raise pfc.exceptions.UI(f"Unsupported url scheme={u.scheme}")

    ssl_context: ssl.SSLContext | None = None
    if u.scheme == "https":
        ssl_context = ssl.create_default_context()

    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

    connect_target = f"{hostname}.{host}:{port}"
    await cli_http.Request(
        method="CONNECT",
        resource_target=connect_target,
        version="HTTP/1.1",
        headers={"Host": connect_target},
        body=b"",
    ).serialize(writer)

    response = await cli_http.Response.deserialize(reader)
    if response.version != "HTTP/1.1":
        raise pfc.exceptions.UI(f"Unable to reach bastion: version={response.version}")
    if response.status_code == 404:
        raise pfc.exceptions.UI(f'"{hostname}" is not registered')
    if response.status_code != 200:
        raise pfc.exceptions.UI(f"Unable to reach bastion: status_code={response.status_code}")

    loop = asyncio.get_running_loop()

    stdin_reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(stdin_reader), sys.stdin.buffer)
    stdout_transport, _ = await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout.buffer)

    async def forward_stdin() -> None:
        while True:
            data = await stdin_reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        try:
            writer.write_eof()
        except (NotImplementedError, OSError):
            writer.close()

    async def forward_stdout() -> None:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            stdout_transport.write(data)

    async def _run_both() -> None:
        await asyncio.gather(forward_stdin(), forward_stdout())

    gather_task: asyncio.Task[None] = asyncio.create_task(_run_both())

    def signal_handler() -> None:
        gather_task.cancel()

    loop.add_signal_handler(signal.SIGTERM, signal_handler)
    loop.add_signal_handler(signal.SIGINT, signal_handler)
    try:
        await gather_task
    except asyncio.CancelledError:
        pass


def _connect_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    factory = client.Factory(c, timeout=args.timeout)
    login.ensure_session(c, factory)
    asyncio.run(connect_async(args.url, args.hostname))


def add_subparser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    register_parser = sub.add_parser("register", help="Register with bastions")
    register_parser.add_argument("-p", "--port", type=int, default=2222, help="Local port to listen on")
    register_parser.add_argument(
        "-i",
        "--poll-interval",
        type=int,
        default=30,
        help="Interval in seconds to poll for bastions",
    )
    register_parser.set_defaults(func=_register_function)

    connect_parser = sub.add_parser("connect", help="Connect via bastion")
    connect_parser.add_argument("--url", required=True, help="Bastion URL")
    connect_parser.add_argument("--hostname", required=True, help="Target hostname")
    connect_parser.set_defaults(func=_connect_function)
