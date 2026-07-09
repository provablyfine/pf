from __future__ import annotations

import argparse
import asyncio
import base64
import functools
import importlib.resources
import json
import logging
import os
import pathlib
import shutil
import signal
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


def _pf_binary() -> str:
    # we do this because we do not want to rely on sys.argv[0] which can be
    # spoofed by the code that invoked this script
    try:
        main = sys.modules["__main__"].__file__
        assert main is not None
        return main
    except (KeyError, AttributeError):
        # This happens if Python was started interactively (REPL) or via -c
        raise pfc.exceptions.UI("Unable to find current entry point to execute get-token")


def _write_frpc_config(
    configuration: str,
    path: str,
    server_addr: str,
    server_port: int,
    transport_protocol: str,
    user: str,
    identity_name: str,
    local_port: int,
) -> None:
    config = {
        "serverAddr": server_addr,
        "serverPort": server_port,
        "user": user,
        "auth": {
            "method": "oidc",
            "oidc": {
                "tokenSource": {
                    "type": "exec",
                    "exec": {
                        "command": sys.executable,
                        "args": [
                            _pf_binary(),
                            "-c",
                            configuration,
                            "bastion",
                            "get-token",
                            "--hostname",
                            identity_name,
                        ],
                    },
                },
            },
        },
        "transport": {
            "protocol": transport_protocol,
            "tcpMux": True,
            "tcpMuxKeepaliveInterval": 5,
            "dialServerKeepalive": 30,
            "dialServerTimeout": 10,
        },
        "proxies": [
            {
                "name": "ssh",
                "type": "tcpmux",
                "multiplexer": "httpconnect",
                "localIP": "127.0.0.1",
                "localPort": local_port,
                "customDomains": [f"{user}.{server_addr}"],
            }
        ],
    }
    with open(path, "w") as f:
        json.dump(config, f)


async def _manage_frpc(
    configuration: str,
    sc: pfc.AsyncSessionClient,
    bastion_url: str,
    identity_name: str,
    local_port: int,
    stop_event: asyncio.Event,
    frps_bind_port: int | None = None,
) -> None:
    u = urllib.parse.urlsplit(bastion_url)
    server_addr = u.hostname or bastion_url
    server_port = frps_bind_port or u.port or (443 if u.scheme == "https" else 80)
    transport_protocol = "wss" if u.scheme == "https" else "tcp"

    config_fd, config_path = tempfile.mkstemp(suffix=".json", prefix="frpc-")
    os.close(config_fd)

    try:
        while not stop_event.is_set():
            try:
                token_response = await sc.get_self_token("bastion", hostname=identity_name)
                frpc_user = _jwt_audience(token_response.token)
            except Exception as e:
                logger.warning(f"Failed to obtain frpc token for bastion={bastion_url}: {e}")
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=5)
                except TimeoutError:
                    pass
                continue

            _write_frpc_config(
                configuration,
                config_path,
                server_addr,
                server_port,
                transport_protocol,
                frpc_user,
                identity_name,
                local_port,
            )

            env = dict(os.environ)
            for _var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
                env.pop(_var, None)
            env["NO_PROXY"] = "*"
            process = await asyncio.create_subprocess_exec(
                _frpc_binary(),
                "--allow-unsafe=TokenSourceExec",
                "-c",
                config_path,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            logger.info(f"frpc started for bastion={bastion_url} identity={identity_name}")

            frpc_output: bytes = b""
            try:
                while not stop_event.is_set() and process.returncode is None:
                    try:
                        await asyncio.wait_for(stop_event.wait(), timeout=5)
                    except TimeoutError:
                        pass
            finally:
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=5)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
                if process.stdout is not None:
                    frpc_output = await process.stdout.read()

            if process.returncode != 0:
                logger.warning(
                    f"frpc exited rc={process.returncode} for bastion={bastion_url}:"
                    f" {frpc_output.decode(errors='replace')!r}"
                )
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
                    task = asyncio.create_task(
                        _manage_frpc(
                            args.config, sc, bastion.url, identity_name, args.port, stop_event, args.frps_bind_port
                        )
                    )
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


async def connect_async(url: str, hostname: str, sc: pfc.AsyncSessionClient) -> None:
    u = urllib.parse.urlsplit(url)
    host = u.hostname or url
    scheme_port = 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
    port = u.port if u.port is not None else scheme_port

    if u.scheme not in ["http", "https"]:
        raise pfc.exceptions.UI(f"Unsupported url scheme={u.scheme}")

    ssl_context: ssl.SSLContext | None = None
    if u.scheme == "https":
        ssl_context = ssl.create_default_context()

    token_response = await sc.get_self_token("bastion", hostname=hostname)
    frpc_user = _jwt_audience(token_response.token)

    reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

    connect_target = f"{frpc_user}.{host}:{port}"
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

    async def _run() -> None:
        sc = factory.async_session()
        await connect_async(args.url, args.hostname, sc)

    asyncio.run(_run())


def _get_token_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    factory = client.Factory(c, timeout=args.timeout)
    login.ensure_session(c, factory)
    token_response = factory.session().get_self_token("bastion", hostname=args.hostname)
    print(token_response.token, end="")


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
    register_parser.add_argument(
        "--frps-bind-port",
        type=int,
        default=None,
        help="frps control port for frpc (overrides the port in the bastion URL;"
        " needed when the HTTP CONNECT port and the frpc control port differ)",
    )
    register_parser.set_defaults(func=_register_function)

    connect_parser = sub.add_parser("connect", help="Connect via bastion")
    connect_parser.add_argument("--url", required=True, help="Bastion URL")
    connect_parser.add_argument("--hostname", required=True, help="Target hostname")
    connect_parser.set_defaults(func=_connect_function)

    get_token_parser = sub.add_parser("get-token", help="Print a bastion JWT to stdout")
    get_token_parser.add_argument("--hostname", required=True, help="Identity hostname")
    get_token_parser.set_defaults(func=_get_token_function)
