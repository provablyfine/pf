import argparse
import asyncio
import logging
import signal
import ssl
import sys
import types
import typing

import websockets.asyncio.client

from ... import bastion, client
from .. import login


class BastionDict(typing.TypedDict):
    id: int
    register_url: str
    connect_url: str | None
    ssh_proxy_jump: str | None

logger = logging.getLogger(__name__)


def _get_bastions(auth: client.HttpClient) -> list[BastionDict]:
    response = auth.get(f"{auth.directory.identity}/self/bastions")
    if response.status_code != 200:
        raise client.exceptions.UI(response.json().get("title", "Failed to get bastions"))
    return response.json().get("bastions", [])


def _get_token(auth: client.HttpClient) -> str:
    response = auth.get(
        f"{auth.directory.identity}/self/token",
        params={"service": "bastion"},
    )
    if response.status_code != 200:
        raise client.exceptions.UI(response.json().get("title", "Failed to get token"))
    return response.json()["token"]


async def _handle_channel(ch: bastion.mux.Channel, local_port: int) -> None:
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
    except Exception as e:
        logger.debug(f"Cannot connect to local port {local_port}: {e}")
        await ch.close()
        return

    async def tcp_to_ch() -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                await ch.send(data)
        except Exception:
            pass
        finally:
            await ch.close()

    async def ch_to_tcp() -> None:
        try:
            while True:
                data = await ch.receive()
                writer.write(data)
                await writer.drain()
        except (bastion.mux.MuxError, bastion.mux.ChannelError):
            pass
        finally:
            try:
                writer.write_eof()
            except Exception:
                pass

    try:
        await asyncio.gather(tcp_to_ch(), ch_to_tcp())
    finally:
        writer.close()


async def _register_bastion(register_url: str, token: str, local_port: int) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    async with websockets.asyncio.client.connect(
        register_url,
        additional_headers=headers,
        subprotocols=("mux-ssh",),  # type: ignore[arg-type]
    ) as ws:
        mux_client = bastion.mux.Client(ws)
        try:
            while not mux_client.is_closed:
                ch = await mux_client.accept_channel()
                asyncio.create_task(_handle_channel(ch, local_port))  # noqa: RUF006
        except bastion.mux.MuxError:
            pass


@client.ssh_utils.exception
def _register_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)

    if not login.has_valid_session(c):
        raise client.exceptions.UI("Not logged in. Run 'pf login' first.")

    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)

    active_tasks: dict[int, asyncio.Task[None]] = {}
    stop_event = asyncio.Event()

    def signal_handler(sig: int, frame: types.FrameType | None) -> None:
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    async def poll_bastions():
        while not stop_event.is_set():
            try:
                current_bastions = {b["id"]: b for b in _get_bastions(auth)}

                token = _get_token(auth)

                for bastion_id in list(active_tasks.keys()):
                    if bastion_id in current_bastions:
                        continue
                    task = active_tasks.pop(bastion_id)
                    task.cancel()
                    print(f"Bastion {bastion_id} removed")

                for bastion_id, bastion in current_bastions.items():
                    if bastion_id in active_tasks:
                        continue
                    register_url = bastion.get("register_url")
                    if register_url is None:
                        continue

                    task = asyncio.create_task(_register_bastion(register_url, token, args.port))
                    active_tasks[bastion_id] = task
                    print(f"Registered bastion {bastion_id}")
            except Exception as e:
                logger.debug(f"Poll error: {e}")

            await asyncio.sleep(args.poll_interval)

    asyncio.run(poll_bastions())

    signal.signal(signal.SIGINT, old_handler)
    signal.signal(signal.SIGTERM, old_handler)


async def _connect_async(url: str, token: str, hostname: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    connect_url = f"{url}?hostname={hostname}"
    ssl_context = ssl.create_default_context() if url.startswith("wss://") else None

    loop = asyncio.get_running_loop()

    stdin_reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(stdin_reader), sys.stdin.buffer)

    stdout_writer, _ = await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout.buffer)

    async with websockets.asyncio.client.connect(
        connect_url,
        ssl=ssl_context,
        additional_headers=headers,
        subprotocols=("mux-ssh",),  # type: ignore[arg-type]
    ) as ws:
        mux_client = bastion.mux.Client(ws)
        ch = await mux_client.accept_channel()

        async def forward_stdin() -> None:
            logger.debug("start forward stdin")
            try:
                while True:
                    data = await stdin_reader.read(4096)
                    if not data:
                        break
                    logger.debug(f"stdin: read={len(data)}")
                    await ch.send(data)
                    logger.debug(f"ch: write={len(data)}")
            except Exception as e:
                logger.debug(f"stdin exception={e}")
            finally:
                await ch.close()

        async def forward_stdout() -> None:
            logger.debug("start forward stdout")
            try:
                while True:
                    data = await ch.receive()
                    logger.debug(f"ch: read={len(data)}")
                    stdout_writer.write(data)
                    logger.debug(f"stdout: write={len(data)}")
            except (bastion.mux.ChannelError, bastion.mux.MuxError):
                pass

        await asyncio.gather(forward_stdin(), forward_stdout())


def _connect_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)

    if not login.has_valid_session(c):
        raise client.exceptions.UI("Not logged in. Run 'pf login' first.")

    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)
    token = _get_token(auth)
    asyncio.run(_connect_async(args.url, token, args.hostname))


def add_subparser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser("bastion", help="Bastion management")
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
