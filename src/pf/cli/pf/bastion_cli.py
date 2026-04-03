import asyncio
import base64
import json
import logging
import signal
import ssl
import sys

import websockets

from ... import client
from .. import login

logger = logging.getLogger(__name__)


def _get_bastions(api: client.Client, auth: client.HttpClient) -> list[dict]:
    response = auth.get(f"{auth.directory.identity}/self")
    if response.status_code != 200:
        raise client.exceptions.UI(response.json().get("title", "Failed to get bastions"))
    return response.json().get("bastion_list", [])


def _get_token(api: client.Client, auth: client.HttpClient, bastion_id: int) -> str:
    response = auth.get(
        f"{auth.directory.identity}/self/token",
        params={"service": f"bastion:{bastion_id}"},
    )
    if response.status_code != 200:
        raise client.exceptions.UI(response.json().get("title", "Failed to get token"))
    return response.json()["token"]


async def _register_bastion(register_url: str, token: str, local_port: int) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    async with websockets.connect(
        register_url,
        extra_headers=headers,
        subprotocols=("mux-ssh",),  # type: ignore[arg-type]
    ) as ws:
        # Single serialised outbound queue — avoids concurrent ws.send() calls.
        tx_queue: asyncio.Queue[dict | None] = asyncio.Queue()

        # Per-channel state
        writers: dict[str, asyncio.StreamWriter] = {}
        tx_semaphores: dict[str, asyncio.Semaphore] = {}
        consumed: dict[str, int] = {}  # data frames received since last ack
        ack_thresholds: dict[str, int] = {}
        channel_tasks: list[asyncio.Task] = []

        async def _writer() -> None:
            while True:
                msg = await tx_queue.get()
                if msg is None:
                    break
                await ws.send(json.dumps(msg))

        async def _tcp_to_mux(channel_id: str, reader: asyncio.StreamReader) -> None:
            try:
                while True:
                    data = await reader.read(4096)
                    if not data:
                        break
                    await tx_semaphores[channel_id].acquire()
                    await tx_queue.put(
                        {
                            "type": "data",
                            "channel_id": channel_id,
                            "payload": base64.b64encode(data).decode(),
                        }
                    )
            except Exception:
                pass
            finally:
                await tx_queue.put({"type": "close", "channel_id": channel_id})

        writer_task = asyncio.create_task(_writer())
        try:
            async for raw in ws:
                msg = json.loads(raw)
                msg_type = msg.get("type")
                channel_id = msg.get("channel_id")

                if msg_type == "open":
                    try:
                        reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
                    except Exception as e:
                        logger.debug(f"Cannot connect to local port {local_port}: {e}")
                        await tx_queue.put({"type": "close", "channel_id": channel_id})
                        continue
                    writers[channel_id] = writer
                    tx_semaphores[channel_id] = asyncio.Semaphore(msg["credits"])
                    consumed[channel_id] = 0
                    ack_thresholds[channel_id] = msg["ack_threshold"]
                    channel_tasks.append(asyncio.create_task(_tcp_to_mux(channel_id, reader)))

                elif msg_type == "data" and channel_id in writers:
                    writers[channel_id].write(base64.b64decode(msg["payload"]))
                    await writers[channel_id].drain()
                    consumed[channel_id] += 1
                    if consumed[channel_id] >= ack_thresholds[channel_id]:
                        await tx_queue.put(
                            {
                                "type": "ack",
                                "channel_id": channel_id,
                                "credits": consumed[channel_id],
                            }
                        )
                        consumed[channel_id] = 0

                elif msg_type == "ack" and channel_id in tx_semaphores:
                    for _ in range(msg.get("credits", 1)):
                        tx_semaphores[channel_id].release()

                elif msg_type in ("close", "error") and channel_id in writers:
                    writers.pop(channel_id).close()
                    tx_semaphores.pop(channel_id, None)
                    consumed.pop(channel_id, None)
                    ack_thresholds.pop(channel_id, None)

        finally:
            await tx_queue.put(None)
            await writer_task
            for t in channel_tasks:
                t.cancel()
            for w in writers.values():
                w.close()


@client.ssh_utils.exception
def _register_function(args):
    c = client.Config.load(args.config)

    if not login.has_valid_session(c):
        raise client.exceptions.UI("Not logged in. Run 'pf login' first.")

    api = client.Client(c)
    auth = api.session_auth(c.session_key)

    bastion_list = _get_bastions(api, auth)
    if not bastion_list:
        print("No bastions found for this identity")
        return

    active_tasks: dict[int, asyncio.Task] = {}
    stop_event = asyncio.Event()

    def signal_handler(sig, frame):
        stop_event.set()

    old_handler = signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    async def poll_bastions():
        while not stop_event.is_set():
            try:
                current_bastions = {b["id"]: b for b in _get_bastions(api, auth)}

                for bastion_id in list(active_tasks.keys()):
                    if bastion_id not in current_bastions:
                        task = active_tasks.pop(bastion_id)
                        task.cancel()
                        print(f"Bastion {bastion_id} removed")

                for bastion_id, bastion in current_bastions.items():
                    if bastion_id not in active_tasks:
                        register_url = bastion.get("register_url")
                        if not register_url:
                            continue

                        token = _get_token(api, auth, bastion_id)
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

    ssl_context = ssl.create_default_context()
    headers = {"Authorization": f"Bearer {token}"}

    async with websockets.connect(
        url,
        ssl=ssl_context,
        extra_headers=headers,
        subprotocols=("ssh",),  # type: ignore[arg-type]
    ) as ws:

        async def forward_stdin():
            try:
                while True:
                    data = await sys.stdin.buffer.read(4096)
                    if not data:
                        break
                    await ws.send_bytes(data)
            except Exception:
                pass
            finally:
                # XXX: should we close stdin/stdout ?
                # to make sure gather completes ?
                await ws.close()

        async def forward_stdout():
            try:
                while True:
                    data = await ws.receive_bytes()
                    if not data:
                        break
                    await sys.stdout.buffer.write(data)
                    await sys.stdout.buffer.flush()
            except Exception:
                pass
            finally:
                # XXX: should we close stdin/stdout ?
                # to make sure gather completes ?
                await ws.close()

        await asyncio.gather(forward_stdin(), forward_stdout())


def _connect_function(args):
    asyncio.run(_connect_async(args.url, args.token, args.hostname))


def add_subparser(subparsers):
    parser = subparsers.add_parser("bastion", help="Bastion management")
    sub = parser.add_subparsers(required=True)

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
    connect_parser.add_argument("--token", required=True, help="Bastion token")
    connect_parser.add_argument("--hostname", required=True, help="Target hostname")
    connect_parser.set_defaults(func=_connect_function)
