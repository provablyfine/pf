"""
WebSocket multiplexer — server-initiated logical channels over a single WebSocket.

Uses the h2 library (HTTP/2) for stream multiplexing and flow control.
The mux.Server acts as the h2 CLIENT (odd stream IDs 1, 3, 5, …): it opens
channels by sending HEADERS frames. The bastion agent (demux.Client) acts as
the h2 SERVER and receives channels via RequestReceived events.

Transport: h2 binary frames are sent as WebSocket binary messages.

Channel lifecycle:
  open:  Server calls send_headers() with channel metadata as x-pf-meta header.
  data:  Both sides exchange DATA frames.
  close: Sender calls send_data(end_stream=True); receiver gets StreamEnded.
         Either side may call reset_stream() for abrupt termination.

Flow control is handled automatically by h2 (WINDOW_UPDATE frames).
"""

import asyncio
import dataclasses
import json
import logging
import typing

import h2.config
import h2.connection
import h2.events
import h2.exceptions

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class _Sentinel:
    """Injected into a channel RX queue to unblock receive() on connection loss."""

    exc: Exception


_STREAM_ENDED = object()  # signals graceful remote half-close


class MuxError(Exception):
    """The underlying WebSocket connection was lost or explicitly closed."""


class ChannelError(Exception):
    """A specific logical channel was closed or failed."""


class Channel:
    """
    A logical bidirectional channel multiplexed over a single WebSocket.

    Do not instantiate directly — use Server.open_channel().
    """

    def __init__(self, stream_id: int, mux: "Server") -> None:
        self.channel_id = str(stream_id)
        self._stream_id = stream_id
        self._mux = mux
        self._rx: asyncio.Queue[bytes | _Sentinel | object] = asyncio.Queue()
        self._send_closed = False

    async def send(self, payload: bytes) -> None:
        """
        Send a payload to the client on this channel.

        Blocks when the h2 flow control window is exhausted.

        Raises:
            ChannelError: if this channel is already closed.
            MuxError: if the WebSocket connection is lost.
        """
        if self._send_closed:
            raise ChannelError(f"Channel {self.channel_id} is already closed")
        if self._mux._closed.is_set():
            raise MuxError("WebSocket connection is closed")
        await self._mux._send_data(self._stream_id, payload, end_stream=False)

    async def receive(self) -> bytes:
        """
        Receive the next payload sent by the client on this channel.

        Raises:
            ChannelError: if the channel is closed by either side or
                          if the WebSocket connection is lost.
        """
        msg = await self._rx.get()
        if isinstance(msg, _Sentinel):
            raise ChannelError(f"Channel {self.channel_id}: connection lost") from msg.exc
        if msg is _STREAM_ENDED:
            raise ChannelError(f"Channel {self.channel_id} closed by remote")
        assert isinstance(msg, bytes)
        return msg

    async def close(self) -> None:
        """Send END_STREAM to the client and mark this channel as closed."""
        if self._send_closed:
            return
        self._send_closed = True
        try:
            await self._mux._send_data(self._stream_id, b"", end_stream=True)
        except Exception:
            pass

    def _inject(self, item: object) -> None:
        """Enqueue an item into the RX queue (non-blocking, best-effort)."""
        try:
            self._rx.put_nowait(item)
        except asyncio.QueueFull:
            pass


class Server:
    """
    Multiplexes multiple logical channels over a single WebSocket using HTTP/2.

    The Server acts as the h2 CLIENT: it opens channels by sending HEADERS
    frames (stream IDs 1, 3, 5, …). The agent (demux.Client) acts as the h2
    SERVER and receives channels via RequestReceived events.

    The WebSocket object must support:
        await ws.send_bytes(data: bytes)
        await ws.receive_bytes() -> bytes
        await ws.close()
    This matches the FastAPI WebSocket interface.
    """

    def __init__(
        self,
        ws: typing.Any,
    ) -> None:
        self._ws = ws
        self._h2 = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        )
        self._h2.initiate_connection()
        # asyncio.Condition: used as both the h2 lock and a condition variable
        # for flow-control waits. All h2 calls must be made under this condition.
        self._cond: asyncio.Condition = asyncio.Condition()
        self._channels: dict[int, Channel] = {}
        self._closed: asyncio.Event = asyncio.Event()
        self._close_exc: Exception | None = None
        self._tasks = [
            asyncio.create_task(self._reader(), name="mux-reader"),
        ]

    async def open_channel(self, meta: dict | None = None) -> Channel:
        """
        Open a new logical channel and notify the client.

        Metadata is transmitted as the x-pf-meta HTTP header (JSON-encoded).

        Raises MuxError if the WebSocket is already closed.
        """
        if self._closed.is_set():
            raise MuxError("Cannot open channel: WebSocket is closed")

        outdata: bytes
        stream_id: int
        async with self._cond:
            stream_id = self._h2.get_next_available_stream_id()
            self._h2.send_headers(
                stream_id,
                [
                    (":method", "CONNECT"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":authority", "bastion"),
                    ("x-pf-meta", json.dumps(meta or {})),
                ],
            )
            channel = Channel(stream_id, self)
            self._channels[stream_id] = channel
            outdata = self._h2.data_to_send()

        if outdata:
            await self._ws.send_bytes(outdata)

        logger.debug("Opened channel (stream_id=%d)", stream_id)
        return channel

    async def close(self) -> None:
        """Gracefully shut down the mux."""
        if self._closed.is_set():
            return

        for ch in list(self._channels.values()):
            await ch.close()

        outdata: bytes = b""
        async with self._cond:
            try:
                self._h2.close_connection()
                outdata = self._h2.data_to_send()
            except Exception:
                pass
        if outdata:
            try:
                await self._ws.send_bytes(outdata)
            except Exception:
                pass

        self._closed.set()
        async with self._cond:
            self._cond.notify_all()

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

    async def _send_data(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        """
        Send data on a stream, respecting h2 flow control and max frame size.

        Waits (under the condition) when the flow control window is exhausted.
        Sends data in chunks bounded by both the window and max_outbound_frame_size.
        """
        remaining = data
        while True:
            outdata: bytes = b""
            done = False

            async with self._cond:
                if self._closed.is_set():
                    raise MuxError("WebSocket connection is closed")

                # local_flow_control_window already accounts for the
                # connection-level window (returns min of both).
                window = self._h2.local_flow_control_window(stream_id)

                if remaining and window == 0:
                    # Flow control window exhausted — wait for WINDOW_UPDATE.
                    await self._cond.wait()
                    continue

                if remaining:
                    # h2 also enforces max_outbound_frame_size per send_data call.
                    max_chunk = min(window, self._h2.max_outbound_frame_size)
                    chunk = remaining[:max_chunk]
                    remaining = remaining[max_chunk:]
                    last = not remaining
                    try:
                        self._h2.send_data(stream_id, chunk, end_stream=(last and end_stream))
                    except h2.exceptions.ProtocolError as exc:
                        raise ChannelError(str(exc)) from exc
                    done = last
                else:
                    # Empty payload with end_stream flag (graceful close).
                    try:
                        self._h2.send_data(stream_id, b"", end_stream=True)
                    except h2.exceptions.ProtocolError as exc:
                        raise ChannelError(str(exc)) from exc
                    done = True

                outdata = self._h2.data_to_send()

            if outdata:
                await self._ws.send_bytes(outdata)

            if done:
                return
            # Loop to send the remaining data.

    async def _reader(self) -> None:
        """Send h2 client preface, then read and dispatch incoming frames."""
        # Flush the client preface (magic + SETTINGS) generated by initiate_connection().
        async with self._cond:
            outdata = self._h2.data_to_send()
        if outdata:
            try:
                await self._ws.send_bytes(outdata)
            except Exception as exc:
                await self._fail(exc)
                return

        exc_out: Exception = Exception("WebSocket connection closed")
        try:
            while True:
                data = await self._ws.receive_bytes()
                outdata = b""
                async with self._cond:
                    events = self._h2.receive_data(data)
                    for event in events:
                        self._handle_event(event)
                    self._cond.notify_all()
                    outdata = self._h2.data_to_send()
                if outdata:
                    await self._ws.send_bytes(outdata)
        except Exception as exc:
            exc_out = exc
            logger.debug("Mux reader terminated: %s", exc)
        await self._fail(exc_out)

    def _handle_event(self, event: h2.events.Event) -> None:
        """
        Dispatch a single h2 event. Must be called under self._cond.

        Calls notify_all() on WindowUpdated so that any send() blocked on
        flow control can retry.
        """
        if isinstance(event, h2.events.DataReceived):
            ch = self._channels.get(event.stream_id)
            if ch and event.data:
                ch._inject(event.data)
            self._h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            if event.stream_ended:
                if ch:
                    ch._inject(_STREAM_ENDED)
                self._channels.pop(event.stream_id, None)

        elif isinstance(event, h2.events.StreamEnded):
            ch = self._channels.pop(event.stream_id, None)
            if ch:
                ch._inject(_STREAM_ENDED)

        elif isinstance(event, h2.events.StreamReset):
            ch = self._channels.pop(event.stream_id, None)
            if ch:
                ch._inject(_Sentinel(exc=ChannelError(f"Stream {event.stream_id} reset by remote")))

        elif isinstance(event, h2.events.WindowUpdated):
            # Notify any send() coroutine waiting on flow control.
            self._cond.notify_all()

        elif isinstance(event, h2.events.ConnectionTerminated):
            raise ConnectionError(f"h2 connection terminated: {event.error_code}")

        elif isinstance(
            event,
            (
                h2.events.ResponseReceived,
                h2.events.RemoteSettingsChanged,
                h2.events.SettingsAcknowledged,
                h2.events.UnknownFrameReceived,
            ),
        ):
            pass  # Normal handshake / informational events.

        else:
            logger.debug("Mux: unhandled h2 event %r", event)

    async def _fail(self, exc: Exception) -> None:
        """Handle a fatal error: mark closed, unblock all channels and senders."""
        if self._closed.is_set():
            return
        self._closed.set()
        self._close_exc = exc

        sentinel = _Sentinel(exc=exc)
        async with self._cond:
            for ch in self._channels.values():
                ch._inject(sentinel)
            self._channels.clear()
            self._cond.notify_all()

        for t in self._tasks:
            t.cancel()
