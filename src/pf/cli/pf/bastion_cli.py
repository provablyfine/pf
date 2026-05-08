from __future__ import annotations

import argparse
import asyncio
import dataclasses
import logging
import signal
import sys
import types
import urllib.parse

from ... import anet, client
from .. import login

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class Response:
    version: str
    status_code: int
    reason: str
    headers: dict[str, str]
    body: bytes

    @classmethod
    async def deserialize(cls, sock: anet.base.Socket) -> Response:
        try:
            response = await anet.http.Response.deserialize(sock)
        except anet.exceptions.Error as exc:
            raise client.exceptions.UI("Unable to reach bastion") from exc
        return Response(
            version=response.version,
            status_code=response.status_code,
            reason=response.reason,
            headers=response.headers,
            body=response.body,
        )


async def _http_connect(url: str, prefix: str, hostname: str, token: str) -> anet.base.Socket:
    u = urllib.parse.urlsplit(url)
    connect_host = f"{prefix}.{u.hostname}"
    scheme_port = 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
    port = u.port if u.port is not None else scheme_port

    if u.scheme not in ["http", "https"]:
        raise client.exceptions.UI(f"Unsupported url scheme={u.scheme}")

    retval: anet.base.Socket
    sock = anet.socket.socket(anet.socket.Family.INET, anet.socket.Type.STREAM)
    await sock.connect((connect_host, port))

    if u.scheme == "https":
        ssl_context = await anet.ssl.create_default_context()
        # The call below is blocking which is "suboptimal"
        # but the alternatives are not a lot of fun.
        ssl_sock = await ssl_context.wrap_socket(sock, server_hostname=connect_host)
        await ssl_sock.handshake()
        retval = ssl_sock
    elif u.scheme == "http":
        retval = sock
    else:
        assert False

    request = anet.http.Request(
        method="CONNECT",
        resource_target=f"{hostname}:80",
        version="HTTP/1.1",
        body=b"",
        headers={"Host": connect_host, "Proxy-Authorization": f"Bearer {token}"},
    )
    await request.serialize(retval)
    response = await Response.deserialize(retval)
    if response.version != "HTTP/1.1":
        raise client.exceptions.UI(f"Unable to reach bastion: version={response.version}")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to reach bastion: status_code={response.status_code}")
    return retval


async def _handle_channel(mux: anet.mux.Mux, local_id: int, local_port: int) -> None:
    try:
        local_reader, local_writer = await asyncio.open_connection("127.0.0.1", local_port)
    except Exception as e:
        logger.debug(f"Cannot connect to local port {local_port}: {e}")
        await mux.channel_close(local_id)
        return

    async def local_to_remote() -> None:
        try:
            while True:
                data = await local_reader.read(4096)
                if not data:
                    break
                await mux.channel_write(local_id, data)
        except Exception:
            pass
        finally:
            await mux.channel_close(local_id)

    async def remote_to_local() -> None:
        while True:
            data = await mux.channel_read(local_id)
            if data == b"":
                break
            local_writer.write(data)
            await local_writer.drain()
        try:
            local_writer.write_eof()
        except Exception:
            pass

    try:
        await asyncio.gather(remote_to_local(), local_to_remote())
    finally:
        local_writer.close()


async def register_async(url: str, token: str, local_port: int) -> None:
    sock = await _http_connect(url, "register", "self", token)
    socket_name = f"bastion-server-{id(sock)}"
    anet.sockets.store.add(socket_name, sock)
    try:
        server = anet.mux.Mux.create(socket_name)
        background_tasks: set[asyncio.Task[None]] = set()
        while True:
            local_id = await server.channel_accept()
            task = asyncio.create_task(_handle_channel(server, local_id, local_port))
            background_tasks.add(task)
            task.add_done_callback(background_tasks.discard)
    finally:
        anet.sockets.store.remove(socket_name)


@client.ssh_utils.exception
def _register_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)

    if not login.has_valid_session(c):
        raise client.exceptions.UI("Not logged in. Run 'pf login' first.")

    sc = client.sync.Client(c, timeout=args.timeout)

    active_tasks: dict[int, asyncio.Task[None]] = {}
    stop_event = asyncio.Event()

    def signal_handler(sig: int, frame: types.FrameType | None) -> None:
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    async def poll_bastions():
        while not stop_event.is_set():
            try:
                bastions_response = sc.list_self_bastions()
                current_bastions = {b.id: b for b in bastions_response.bastions}

                token_response = sc.get_self_token("bastion")
                token = token_response.token

                for bastion_id in list(active_tasks.keys()):
                    if bastion_id in current_bastions:
                        continue
                    task = active_tasks.pop(bastion_id)
                    task.cancel()
                    print(f"Bastion {bastion_id} removed")

                for bastion_id, bastion in current_bastions.items():
                    if bastion_id in active_tasks:
                        continue

                    task = asyncio.create_task(register_async(bastion.url, token, args.port))
                    active_tasks[bastion_id] = task
                    print(f"Registered bastion {bastion_id}")
            except Exception as e:
                logger.debug(f"Poll error: {e}")

            await asyncio.sleep(args.poll_interval)

    asyncio.run(poll_bastions())

    signal.signal(signal.SIGINT, old_handler)
    signal.signal(signal.SIGTERM, old_handler)


async def connect_async(url: str, token: str, hostname: str) -> None:
    sock = await _http_connect(url, "connect", hostname, token)

    loop = asyncio.get_running_loop()

    stdin_reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(stdin_reader), sys.stdin.buffer)
    stdout_writer, _ = await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout.buffer)

    async def forward_stdin() -> None:
        logger.debug("start forward stdin")
        while True:
            data = await stdin_reader.read(4096)
            if data == b"":
                break
            logger.debug(f"stdin: read={len(data)}")
            await sock.send(data)
            logger.debug(f"ch: write={len(data)}")
        await sock.shutdown(anet.base.Shut.WR)

    async def forward_stdout() -> None:
        logger.debug("start forward stdout")
        while True:
            data = await sock.recv(4096)
            if data == b"":
                break
            logger.debug(f"ch: read={len(data)}")
            stdout_writer.write(data)
            logger.debug(f"stdout: write={len(data)}")

    await asyncio.gather(forward_stdin(), forward_stdout())


def _connect_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)

    if not login.has_valid_session(c):
        raise client.exceptions.UI("Not logged in. Run 'pf login' first.")

    sc = client.sync.Client(c, timeout=args.timeout)
    token_response = sc.get_self_token("bastion")
    asyncio.run(connect_async(args.url, token_response.token, args.hostname))


def add_subparser(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(required=True, dest="_cmd2")

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
    connect_parser.add_argument("--url", required=True, help="Bastion connect URL")
    connect_parser.add_argument("--hostname", required=True, help="Target hostname")
    connect_parser.set_defaults(func=_connect_function)
