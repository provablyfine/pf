"""
WebSocket multiplexer — server-initiated logical channels over a single WebSocket.

Protocol messages (JSON):
  Server → Client  {"type": "open",  "channel_id": str, "meta": dict,
                    "credits": int, "ack_threshold": int}
                     Opens a new logical channel.
                     credits       — how many data frames the client may send initially.
                     ack_threshold — client must send an ack after consuming this
                                     many server-sent data frames.
  Both directions  {"type": "data",  "channel_id": str, "payload": any}
  Both directions  {"type": "close", "channel_id": str}
  Both directions  {"type": "ack",   "channel_id": str, "credits": int}
                     Replenishes send credits for the remote side:
                       Client → Server: client consumed N server-sent messages
                                        (replenishes server TX credits)
                       Server → Client: server consumed N client-sent messages
                                        (replenishes client RX credits)
  Server → Client  {"type": "error", "channel_id": str, "reason": str}
                     Signals a per-channel protocol violation; channel is closed.

Backpressure — symmetric credit system (mirrors HTTP/2 flow control):
  TX direction (server → client):
    - Server starts with INITIAL_TX_CREDITS per channel.
    - channel.send() blocks when credits are exhausted.
    - Client sends ack after consuming ACK_THRESHOLD messages, replenishing
      the server's TX credits.

  RX direction (client → server):
    - Server grants the client INITIAL_RX_CREDITS in the open message.
    - Client must not send more messages than it has credits for.
    - Server sends ack back to the client after consuming ACK_THRESHOLD messages
      from the RX queue (in channel.receive()), replenishing client's send credits.
    - If the client violates the credit protocol (RX queue full), the channel is
      closed with an error — no messages are ever dropped silently.
    - The dispatcher never blocks: credit exhaustion is enforced on the sender
      side, so the RX queue should never fill under normal operation.

Error handling:
  - Any WebSocket error (disconnect, timeout, ...) is caught in the reader/writer
    tasks and propagated to all open channels via a sentinel value so that any
    coroutine blocked on channel.receive() or channel.send() is unblocked.
  - All background tasks are cancelled on failure.
"""

import asyncio
import base64
import dataclasses
import logging
import typing
import uuid

logger = logging.getLogger(__name__)


TX_QUEUE_SIZE = 100  # global TX queue depth (messages)
INITIAL_TX_CREDITS = 16  # server→client: initial send credits per channel
INITIAL_RX_CREDITS = 16  # client→server: initial send credits granted to client
ACK_THRESHOLD = 8  # both sides send an ack after consuming this many msgs


class MuxError(Exception):
    """The underlying WebSocket connection was lost or explicitly closed."""


class ChannelError(Exception):
    """A specific logical channel was closed or failed."""


@dataclasses.dataclass
class _ErrorSentinel:
    """Injected into an RX queue to unblock a waiting receive() on failure."""

    exc: Exception


class Channel:
    """
    A logical bidirectional channel multiplexed over a single WebSocket.

    Do not instantiate directly — use ServerMux.open_channel().
    """

    def __init__(
        self,
        channel_id: str,
        tx_queue: asyncio.Queue,  # shared global TX queue
        mux_closed: asyncio.Event,
        initial_tx_credits: int = INITIAL_TX_CREDITS,
        rx_queue_size: int = INITIAL_RX_CREDITS + ACK_THRESHOLD,
    ) -> None:
        self.channel_id = channel_id
        self._tx = tx_queue
        self._mux_closed = mux_closed

        # RX queue — bounded as a last-resort safety net only.
        # Under normal operation it should never fill because the credit system
        # prevents the client from sending more than INITIAL_RX_CREDITS messages
        # before receiving an ack from us.
        self._rx: asyncio.Queue = asyncio.Queue(maxsize=rx_queue_size)

        # TX credits: how many more messages we may send to the client.
        self._tx_credits = asyncio.Semaphore(initial_tx_credits)

        # RX credit accounting: messages consumed since we last acked the client.
        self._rx_consumed = 0

        self._closed = False

    async def send(self, payload: bytes) -> None:
        """
        Send a payload to the client on this channel.

        Blocks when TX credits are exhausted (the client is consuming slowly)
        or when the global TX queue is full.

        Raises:
            ChannelError: if this channel is already closed.
            MuxError: if the WebSocket connection is lost.
        """
        if self._closed:
            raise ChannelError(f"Channel {self.channel_id} is already closed")
        if self._mux_closed.is_set():
            raise MuxError("WebSocket connection is closed")

        # Acquire a TX credit — blocks here if the client is slow to consume.
        await self._tx_credits.acquire()

        # Re-check after the await: the connection may have dropped while
        # we were waiting for a credit.
        if self._mux_closed.is_set():
            raise MuxError("WebSocket connection lost while waiting for TX credit")
        if self._closed:
            raise ChannelError(f"Channel {self.channel_id} closed while waiting for TX credit")

        # Enqueue for the writer task; also blocks if the global TX queue is full.
        await self._tx.put(
            {
                "type": "data",
                "channel_id": self.channel_id,
                "payload": base64.b64encode(payload).decode("ascii"),
            }
        )

    async def receive(self) -> bytes:
        """
        Receive the next payload sent by the client on this channel.

        After consuming ACK_THRESHOLD messages, sends an ack back to the client
        to replenish its RX send credits (symmetric backpressure).

        Raises:
            ChannelError: if the channel is closed by either side or if the
                          WebSocket connection is lost.
        """
        msg = await self._rx.get()

        if isinstance(msg, _ErrorSentinel):
            raise ChannelError(f"Channel {self.channel_id}: connection lost") from msg.exc

        if msg.get("type") == "close":
            self._closed = True
            raise ChannelError(f"Channel {self.channel_id} closed by remote")

        # Replenish client RX credits in batches to amortise ack overhead.
        self._rx_consumed += 1
        if self._rx_consumed >= ACK_THRESHOLD:
            await self._send_rx_ack(self._rx_consumed)
            self._rx_consumed = 0

        return base64.b64decode(msg["payload"].encode("ascii"))

    async def close(self) -> None:
        """Send a close frame to the client and mark this channel as closed."""
        if self._closed:
            return
        self._closed = True
        # Flush any pending RX credit acks before the close frame.
        if self._rx_consumed > 0:
            await self._send_rx_ack(self._rx_consumed)
            self._rx_consumed = 0
        try:
            await self._tx.put({"type": "close", "channel_id": self.channel_id})
        except Exception:
            pass

    def _replenish_tx_credits(self, n: int) -> None:
        """Restore TX credits when an ack arrives from the client."""
        for _ in range(n):
            self._tx_credits.release()

    def _inject_sentinel(self, exc: Exception) -> None:
        """Unblock any coroutine waiting on receive() by injecting a sentinel."""
        try:
            self._rx.put_nowait(_ErrorSentinel(exc=exc))
        except asyncio.QueueFull:
            pass  # channel already has a sentinel or is fully drained

    async def _send_rx_ack(self, credits: int) -> None:
        """Send an ack to replenish the client's RX send credits."""
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


class Server:
    """
    Multiplexes multiple logical channels over a single WebSocket.

    The server is always the initiator of logical channels. The client receives
    an "open" frame and may then send data back on that channel within its
    granted credit budget.

    The WebSocket object must support send_json(dict) and receive_json() → dict.
    """

    def __init__(
        self,
        ws: typing.Any,
        tx_queue_size: int = TX_QUEUE_SIZE,
        initial_tx_credits: int = INITIAL_TX_CREDITS,
        initial_rx_credits: int = INITIAL_RX_CREDITS,
    ) -> None:
        self._ws = ws
        self._initial_tx_credits = initial_tx_credits
        self._initial_rx_credits = initial_rx_credits

        # Single bounded queue shared by all channels for outbound messages.
        # Bounded so that a slow WebSocket send does not allow unbounded memory growth.
        self._tx_queue: asyncio.Queue = asyncio.Queue(maxsize=tx_queue_size)

        self._channels: dict[str, Channel] = {}
        self._closed = asyncio.Event()
        self._close_exc: Exception | None = None

        self._tasks = [
            asyncio.create_task(self._writer(), name="mux-writer"),
            asyncio.create_task(self._reader(), name="mux-reader"),
        ]

    async def open_channel(
        self,
        meta: dict | None = None,
    ) -> Channel:
        """
        Open a new logical channel and notify the client.

        The "open" frame carries the initial RX credits granted to the client,
        telling it how many messages it may send before waiting for an ack.

        Raises MuxError if the WebSocket is already closed.
        """
        if self._closed.is_set():
            raise MuxError("Cannot open channel: WebSocket is closed")

        channel_id = str(uuid.uuid4())
        channel = Channel(
            channel_id=channel_id,
            tx_queue=self._tx_queue,
            mux_closed=self._closed,
            initial_tx_credits=self._initial_tx_credits,
            rx_queue_size=self._initial_rx_credits + ACK_THRESHOLD,
        )
        self._channels[channel_id] = channel

        await self._tx_queue.put(
            {
                "type": "open",
                "channel_id": channel_id,
                "meta": meta or {},
                "credits": self._initial_rx_credits,  # RX credits granted to client
                "ack_threshold": ACK_THRESHOLD,
            }
        )
        logger.debug(
            "Opened channel %s (tx_credits=%d, rx_credits=%d)",
            channel_id,
            self._initial_tx_credits,
            self._initial_rx_credits,
        )
        return channel

    async def close(self) -> None:
        """
        Gracefully shut down the mux.

        Sends close frames for all open channels, drains the TX queue, then
        closes the underlying WebSocket.
        """
        if self._closed.is_set():
            return

        for ch in list(self._channels.values()):
            await ch.close()

        # Push a None sentinel so the writer exits cleanly after draining.
        await self._tx_queue.put(None)

        writer_task = next((t for t in self._tasks if t.get_name() == "mux-writer"), None)
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
        """Drain the TX queue and write frames to the WebSocket."""
        try:
            while True:
                msg = await self._tx_queue.get()
                if msg is None:  # shutdown sentinel from close()
                    break
                await self._ws.send_json(msg)
        except Exception as exc:
            logger.warning("Mux writer failed: %s", exc)
            await self._fail(exc)

    async def _reader(self) -> None:
        """Read frames from the WebSocket and dispatch to channels."""
        try:
            while True:
                msg = await self._ws.receive_json()
                await self._dispatch(msg)
        except Exception as exc:
            logger.warning("Mux reader failed: %s", exc)
            await self._fail(exc)

    async def _dispatch(self, msg: dict) -> None:
        """
        Route an inbound frame to the appropriate channel.

        Must never block — blocking here would stall all channels
        (head-of-line blocking on the shared reader loop).

        If the client sends data beyond its granted credits the RX queue will
        be full. This is a protocol violation: we close the offending channel
        with an error rather than silently dropping the message.
        """
        msg_type = msg.get("type")
        channel_id = msg.get("channel_id")
        ch = self._channels.get(channel_id) if channel_id else None

        if msg_type == "data":
            if ch is None:
                logger.warning("Data on unknown channel %s — ignoring", channel_id)
                return
            try:
                ch._rx.put_nowait(msg)
            except asyncio.QueueFull:
                # Client sent beyond its credit budget — protocol violation.
                logger.error(
                    "Channel %s: RX queue full — client violated flow control, closing channel",
                    channel_id,
                )
                await self._close_channel_with_error(ch, "flow control violation")

        elif msg_type == "ack":
            # Client replenishing our TX credits for this channel.
            if ch:
                ch._replenish_tx_credits(msg.get("credits", 1))
            else:
                logger.warning("Ack on unknown channel %s — ignoring", channel_id)

        elif msg_type == "close":
            if ch:
                ch._rx.put_nowait(msg)
                self._channels.pop(channel_id, None)  # type: ignore[arg-type]
                logger.debug("Channel %s closed by client", channel_id)

        else:
            logger.warning("Unknown message type %r for channel %s — ignoring", msg_type, channel_id)

    async def _close_channel_with_error(self, ch: Channel, reason: str) -> None:
        """Send an error frame to the client and tear down the channel."""
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
        """
        Handle a fatal WebSocket error.

        Marks the mux as closed, injects a sentinel into every open channel's
        RX queue (unblocking any pending receive() calls), and cancels all
        background tasks.
        """
        if self._closed.is_set():
            return
        self._closed.set()
        self._close_exc = exc

        for ch in self._channels.values():
            ch._inject_sentinel(exc)
        self._channels.clear()

        for t in self._tasks:
            t.cancel()
