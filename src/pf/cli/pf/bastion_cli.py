import argparse
import asyncio
import logging
import signal
import ssl
import sys
import types
import urllib.parse
import socket

from ... import bastion, client
from .. import login

logger = logging.getLogger(__name__)


async def _http_connect(url: str, prefix: str, hostname: str, token: str) -> bastion.tcp.TcpSocket:
    u = urllib.parse.urlsplit(url)
    connect_host = f"{prefix}.{u.hostname}"
    ssl_context = ssl.create_default_context() if u.scheme == "https" else None
    scheme_port = 443 if u.scheme == "https" else 80 if u.scheme == "http" else None
    port = u.port if u.port is not None else scheme_port

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    await asyncio.sock_connect(sock, (connect_host, port))
    if u.scheme == "https":
        ssl_context = ssl.create_default_context()
        sock.setblocking(True)
        # The call below is blocking which is "suboptimal"
        # but the alternatives are not a lot of fun.
        sock = ssl_context.wrap_socket(sock, server_hostname=connect_host)
    lines = [
        f"CONNECT {hostname}:80 HTTP/1.1",
        f"Host: {connect_host}",
        f"Proxy-Authorization: Bearer {token}",
        ""
    ]
    sock.setblocking(False)
    wrapper = bastion.tcp.TcpSocket(sock)
    wrapper.send(b"\r\n".join(line.encode("ascii") for line in lines))
    http = bastion.http.LineReader(wrapper)
    status = http.read()
    items = status.rstrip(b"\r\n").decode("ascii").split(" ")
    if len(items) != 3:
        raise client.exceptions.UI(f"Unable to reach bastion: {status.decode('ascii')}")
    version, status_code, reason = items
    if status_code != "200":
        raise client.exceptions.UI(f"Unable to reach bastion: status_code={status_code}")

    return wrapper


async def _handle_channel(remote: bastion.channel.Channel, local_port: int) -> None:
    try:
        local_reader, local_writer = await asyncio.open_connection("127.0.0.1", local_port)
    except Exception as e:
        logger.debug(f"Cannot connect to local port {local_port}: {e}")
        await remote.close()
        return

    async def local_to_remote() -> None:
        try:
            while True:
                data = await local_reader.read(4096)
                if not data:
                    break
                await remote.write(data)
        except Exception:
            pass
        finally:
            await remote.close()

    async def remote_to_local() -> None:
        while True:
            data = await remote.read()
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


async def _register_bastion(register_url: str, token: str, local_port: int) -> None:
    sock = _http_connect(register_url, "register", "self", token)
    server = bastion.channel.Server(sock)
    while True:
        channel = await server.accept()
        asyncio.create_task(_handle_channel(channel, local_port))


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

                    task = asyncio.create_task(_register_bastion(bastion.register_url, token, args.port))
                    active_tasks[bastion_id] = task
                    print(f"Registered bastion {bastion_id}")
            except Exception as e:
                logger.debug(f"Poll error: {e}")

            await asyncio.sleep(args.poll_interval)

    asyncio.run(poll_bastions())

    signal.signal(signal.SIGINT, old_handler)
    signal.signal(signal.SIGTERM, old_handler)


async def _connect_async(url: str, token: str, hostname: str) -> None:
    sock = _http_connect(url, "connect", hostname, token)
    remote_reader, remote_writer = asyncio.open_connection(sock=sock)

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
            await remote_writer.write(data)
            logger.debug(f"ch: write={len(data)}")
        await remote_writer.close()

    async def forward_stdout() -> None:
        logger.debug("start forward stdout")
        while True:
            data = await remote_reader.read()
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
    asyncio.run(_connect_async(args.url, token_response.token, args.hostname))


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
