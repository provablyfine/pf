"""
WebSocket multiplexer — client side.

Symmetric counterpart to mux.Server. The server always opens logical channels
(via "open" frames); this client receives them and exposes them via
accept_channel().

Protocol messages are identical to those in mux.py — see that module for the
full wire format documentation.

The WebSocket object passed to Client must support:
    ws.send(str)         — send a JSON frame
    async for raw in ws  — receive frames (str)
    ws.close()
This matches the websockets.ClientConnection interface.
"""

import asyncio
import base64
import dataclasses
import json
import logging
import typing

logger = logging.getLogger(__name__)

# Sentinel pushed into _open_queue to unblock accept_channel() on failure.
_CLOSED: typing.Any = object()


class MuxError(Exception):
    """The underlying WebSocket connection was lost or explicitly closed."""


class ChannelError(Exception):
    """A specific logical channel was closed or failed."""


@dataclasses.dataclass
class _ErrorSentinel:
    """Injected into a channel RX queue to unblock receive() on failure."""

    exc: Exception


class Channel:
    """
    A logical bidirectional channel multiplexed over a single WebSocket.

    Do not instantiate directly — use Client.accept_channel().
    """

    def __init__(
        self,
        channel_id: str,
        meta: dict,
        tx_queue: asyncio.Queue,
        mux_closed: asyncio.Event,
        initial_tx_credits: int,
        ack_threshold: int,
    ) -> None:
        self.channel_id = channel_id
        self.meta = meta
        self._tx = tx_queue
        self._mux_closed = mux_closed
        self._ack_threshold = ack_threshold

        self._rx: asyncio.Queue = asyncio.Queue(maxsize=ack_threshold * 3)
        self._tx_credits = asyncio.Semaphore(initial_tx_credits)
        self._rx_consumed = 0
        self._closed = False

    async def send(self, payload: bytes) -> None:
        """
        Send payload to the server on this channel.

        Blocks when TX credits are exhausted (server is consuming slowly)
        or when the global TX queue is full.

        Raises:
            ChannelError: if this channel is already closed.
            MuxError: if the WebSocket connection is lost.
        """
        if self._closed:
            raise ChannelError(f"Channel {self.channel_id} is already closed")
        if self._mux_closed.is_set():
            raise MuxError("WebSocket connection is closed")

        await self._tx_credits.acquire()

        if self._mux_closed.is_set():
            raise MuxError("WebSocket connection lost while waiting for TX credit")
        if self._closed:
            raise ChannelError(f"Channel {self.channel_id} closed while waiting for TX credit")

        await self._tx.put(
            {
                "type": "data",
                "channel_id": self.channel_id,
                "payload": base64.b64encode(payload).decode("ascii"),
            }
        )

    async def receive(self) -> bytes:
        """
        Receive the next payload sent by the server on this channel.

        After consuming ack_threshold messages, sends an ack back to replenish
        the server's TX credits.

        Raises:
            ChannelError: if the channel is closed or the connection is lost.
        """
        msg = await self._rx.get()

        if isinstance(msg, _ErrorSentinel):
            raise ChannelError(f"Channel {self.channel_id}: connection lost") from msg.exc

        if msg.get("type") == "close":
            self._closed = True
            raise ChannelError(f"Channel {self.channel_id} closed by remote")

        self._rx_consumed += 1
        if self._rx_consumed >= self._ack_threshold:
            await self._send_rx_ack(self._rx_consumed)
            self._rx_consumed = 0

        return base64.b64decode(msg["payload"].encode("ascii"))

    async def close(self) -> None:
        """Send a close frame to the server and mark this channel as closed."""
        if self._closed:
            return
        self._closed = True
        if self._rx_consumed > 0:
            await self._send_rx_ack(self._rx_consumed)
            self._rx_consumed = 0
        try:
            await self._tx.put({"type": "close", "channel_id": self.channel_id})
        except Exception:
            pass

    def _replenish_tx_credits(self, n: int) -> None:
        """Restore TX credits when an ack arrives from the server."""
        for _ in range(n):
            self._tx_credits.release()

    def _inject_sentinel(self, exc: Exception) -> None:
        """Unblock any coroutine waiting on receive() by injecting a sentinel."""
        try:
            self._rx.put_nowait(_ErrorSentinel(exc=exc))
        except asyncio.QueueFull:
            pass

    async def _send_rx_ack(self, credits: int) -> None:
        try:
            await self._tx.put(
                {
                    "type": "ack",
                    "channel_id": self.channel_id,
                    "credits": credits,
                }
            )
        except Exception:
            pass


class Client:
    """
    Client side of the mux protocol over a websockets-style WebSocket.

    The server opens logical channels by sending "open" frames; each one is
    queued and returned by accept_channel(). The client may then call
    send() / receive() / close() on the resulting Channel.
    """

    def __init__(
        self,
        ws: typing.Any,
        tx_queue_size: int = 100,
    ) -> None:
        self._ws = ws

        self._tx_queue: asyncio.Queue[dict | None] = asyncio.Queue(maxsize=tx_queue_size)
        self._channels: dict[str, Channel] = {}
        self._open_queue: asyncio.Queue = asyncio.Queue()

        self._closed = asyncio.Event()
        self._close_exc: Exception | None = None

        self._tasks = [
            asyncio.create_task(self._writer(), name="demux-writer"),
            asyncio.create_task(self._reader(), name="demux-reader"),
        ]

    async def accept_channel(self) -> Channel:
        """
        Wait for the server to open a new logical channel and return it.

        Raises MuxError if the connection is closed before a channel arrives.
        """
        item = await self._open_queue.get()
        if item is _CLOSED:
            # Put the sentinel back so subsequent callers also raise.
            self._open_queue.put_nowait(_CLOSED)
            raise MuxError("WebSocket connection is closed")
        return item  # type: ignore[return-value]

    async def close(self) -> None:
        """Gracefully shut down the client."""
        if self._closed.is_set():
            return

        for ch in list(self._channels.values()):
            await ch.close()

        await self._tx_queue.put(None)

        writer_task = next((t for t in self._tasks if t.get_name() == "demux-writer"), None)
        if writer_task:
            try:
                await asyncio.wait_for(writer_task, timeout=5.0)
            except (TimeoutError, Exception):
                writer_task.cancel()

        self._closed.set()

        for t in self._tasks:
            t.cancel()

        try:
            await self._ws.close()
        except Exception:
            pass

    @property
    def is_closed(self) -> bool:
        return self._closed.is_set()

    async def wait_closed(self) -> None:
        """Wait until the WebSocket connection is closed (by either side)."""
        await self._closed.wait()

    async def _writer(self) -> None:
        """Drain the TX queue and write JSON frames to the WebSocket."""
        try:
            while True:
                msg = await self._tx_queue.get()
                if msg is None:
                    break
                await self._ws.send(json.dumps(msg))
        except Exception as exc:
            logger.warning("Demux writer failed: %s", exc)
            await self._fail(exc)

    async def _reader(self) -> None:
        """Read frames from the WebSocket and dispatch to channels."""
        exc: Exception = Exception("WebSocket connection closed")
        try:
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    logger.warning("Demux: ignoring non-JSON frame")
                    continue
                await self._dispatch(msg)
        except Exception as e:
            exc = e
            logger.warning("Demux reader failed: %s", exc)
        await self._fail(exc)

    async def _dispatch(self, msg: dict) -> None:
        msg_type = msg.get("type")
        channel_id = msg.get("channel_id")
        ch = self._channels.get(channel_id) if channel_id else None  # type: ignore[arg-type]

        if msg_type == "open":
            channel_id = msg["channel_id"]
            ch = Channel(
                channel_id=channel_id,
                meta=msg.get("meta", {}),
                tx_queue=self._tx_queue,
                mux_closed=self._closed,
                initial_tx_credits=msg["credits"],
                ack_threshold=msg["ack_threshold"],
            )
            self._channels[channel_id] = ch
            await self._open_queue.put(ch)

        elif msg_type == "data" and ch is not None:
            try:
                ch._rx.put_nowait(msg)
            except asyncio.QueueFull:
                logger.error(
                    "Channel %s: RX queue full — server violated flow control, closing channel",
                    channel_id,
                )
                await self._close_channel_with_error(ch, "flow control violation")

        elif msg_type == "ack" and ch is not None:
            ch._replenish_tx_credits(msg.get("credits", 1))

        elif msg_type in ("close", "error") and ch is not None:
            ch._rx.put_nowait(msg)
            self._channels.pop(channel_id, None)  # type: ignore[arg-type]

        else:
            logger.debug("Demux: unhandled frame type=%r channel=%r", msg_type, channel_id)

    async def _close_channel_with_error(self, ch: Channel, reason: str) -> None:
        ch._closed = True
        self._channels.pop(ch.channel_id, None)
        try:
            await self._tx_queue.put(
                {
                    "type": "error",
                    "channel_id": ch.channel_id,
                    "reason": reason,
                }
            )
        except Exception:
            pass

    async def _fail(self, exc: Exception) -> None:
        """Handle a fatal WebSocket error — unblock all waiting coroutines."""
        if self._closed.is_set():
            return
        self._closed.set()
        self._close_exc = exc

        for ch in self._channels.values():
            ch._inject_sentinel(exc)
        self._channels.clear()

        # Unblock any accept_channel() call.
        self._open_queue.put_nowait(_CLOSED)

        for t in self._tasks:
            t.cancel()
