"""
WebSocket multiplexer — client side.

Symmetric counterpart to mux.Server. This client acts as the h2 SERVER:
it receives channels opened by the mux.Server (h2 client) via RequestReceived
events and exposes them via accept_channel().

Transport: h2 binary frames are exchanged as WebSocket binary messages.

The WebSocket object passed to Client must support:
    ws.send(data: bytes)     — send a binary frame
    async for frame in ws    — receive frames (bytes)
    ws.close()
This matches the websockets.ClientConnection interface.
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

_CLOSED: typing.Any = object()  # pushed into _open_queue to unblock accept_channel()


@dataclasses.dataclass
class _Sentinel:
    """Injected into a channel RX queue to unblock receive() on connection loss."""

    exc: Exception


_STREAM_ENDED = object()  # signals graceful remote half-close


class MuxError(Exception):
    """The underlying WebSocket connection was lost or explicitly closed."""


class ChannelError(Exception):
    """A specific logical channel was closed or failed."""


def _meta_from_headers(headers: list) -> dict:
    """Extract channel metadata from h2 request headers."""
    for name, value in headers:
        if name == "x-pf-meta":
            try:
                return json.loads(value)  # type: ignore[arg-type]
            except Exception:
                return {}
    return {}


class Channel:
    """
    A logical bidirectional channel multiplexed over a single WebSocket.

    Do not instantiate directly — use Client.accept_channel().
    """

    def __init__(
        self,
        stream_id: int,
        meta: dict,
        mux: "Client",
    ) -> None:
        self.channel_id = str(stream_id)
        self.meta = meta
        self._stream_id = stream_id
        self._mux = mux
        self._rx: asyncio.Queue[bytes | _Sentinel | object] = asyncio.Queue()
        self._send_closed = False

    async def send(self, payload: bytes) -> None:
        """
        Send payload to the server on this channel.

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
        Receive the next payload sent by the server on this channel.

        Raises:
            ChannelError: if the channel is closed or the connection is lost.
        """
        msg = await self._rx.get()
        if isinstance(msg, _Sentinel):
            raise ChannelError(f"Channel {self.channel_id}: connection lost") from msg.exc
        if msg is _STREAM_ENDED:
            raise ChannelError(f"Channel {self.channel_id} closed by remote")
        assert isinstance(msg, bytes)
        return msg

    async def close(self) -> None:
        """Send END_STREAM to the server and mark this channel as closed."""
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


class Client:
    """
    Client side of the h2-over-WebSocket mux protocol.

    The mux.Server opens logical channels by sending HEADERS frames; each one
    is queued and returned by accept_channel(). The client may then call
    send() / receive() / close() on the resulting Channel.
    """

    def __init__(self, ws: typing.Any) -> None:
        self._ws = ws
        self._h2 = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        self._h2.initiate_connection()
        self._cond: asyncio.Condition = asyncio.Condition()
        self._channels: dict[int, Channel] = {}
        self._open_queue: asyncio.Queue[Channel | object] = asyncio.Queue()
        self._closed: asyncio.Event = asyncio.Event()
        self._close_exc: Exception | None = None

        self._tasks = [
            asyncio.create_task(self._reader(), name="demux-reader"),
        ]

    async def accept_channel(self) -> Channel:
        """
        Wait for the server to open a new logical channel and return it.

        Raises MuxError if the connection is closed before a channel arrives.
        """
        item = await self._open_queue.get()
        if item is _CLOSED:
            self._open_queue.put_nowait(_CLOSED)
            raise MuxError("WebSocket connection is closed")
        assert isinstance(item, Channel)
        return item

    async def close(self) -> None:
        """Gracefully shut down the client."""
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
                await self._ws.send(outdata)
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
        """Send data on a stream, respecting h2 flow control."""
        remaining = data
        while True:
            outdata: bytes = b""
            done = False

            async with self._cond:
                if self._closed.is_set():
                    raise MuxError("WebSocket connection is closed")

                window = self._h2.local_flow_control_window(stream_id)

                if remaining and window == 0:
                    await self._cond.wait()
                    continue

                if remaining:
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
                    try:
                        self._h2.send_data(stream_id, b"", end_stream=True)
                    except h2.exceptions.ProtocolError as exc:
                        raise ChannelError(str(exc)) from exc
                    done = True

                outdata = self._h2.data_to_send()

            if outdata:
                await self._ws.send(outdata)

            if done:
                return

    async def _reader(self) -> None:
        """Send h2 server preface, then read and dispatch incoming frames."""
        # Flush the server's initial SETTINGS generated by initiate_connection().
        async with self._cond:
            outdata = self._h2.data_to_send()
        if outdata:
            try:
                await self._ws.send(outdata)
            except Exception as exc:
                await self._fail(exc)
                return

        exc_out: Exception = Exception("WebSocket connection closed")
        try:
            async for frame in self._ws:
                if not isinstance(frame, bytes):
                    continue  # skip text frames (shouldn't occur)
                outdata = b""
                async with self._cond:
                    events = self._h2.receive_data(frame)
                    for event in events:
                        self._handle_event(event)
                    self._cond.notify_all()
                    outdata = self._h2.data_to_send()
                if outdata:
                    await self._ws.send(outdata)
        except Exception as exc:
            exc_out = exc
            logger.debug("Demux reader terminated: %s", exc)
        await self._fail(exc_out)

    def _handle_event(self, event: h2.events.Event) -> None:
        """
        Dispatch a single h2 event. Must be called under self._cond.
        """
        if isinstance(event, h2.events.RequestReceived):
            stream_id = event.stream_id
            meta = _meta_from_headers(event.headers)
            # Accept the CONNECT tunnel by sending 200 response headers.
            self._h2.send_headers(stream_id, [(":status", "200")])
            channel = Channel(stream_id, meta, self)
            self._channels[stream_id] = channel
            self._open_queue.put_nowait(channel)
            logger.debug("Demux: accepted channel (stream_id=%d)", stream_id)

        elif isinstance(event, h2.events.DataReceived):
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
            self._cond.notify_all()

        elif isinstance(event, h2.events.ConnectionTerminated):
            raise ConnectionError(f"h2 connection terminated: {event.error_code}")

        elif isinstance(
            event,
            (
                h2.events.RemoteSettingsChanged,
                h2.events.SettingsAcknowledged,
                h2.events.UnknownFrameReceived,
            ),
        ):
            pass

        else:
            logger.debug("Demux: unhandled h2 event %r", event)

    async def _fail(self, exc: Exception) -> None:
        """Handle a fatal error: mark closed, unblock all channels and accept_channel()."""
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

        self._open_queue.put_nowait(_CLOSED)

        for t in self._tasks:
            t.cancel()
