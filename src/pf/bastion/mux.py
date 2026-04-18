"""
WebSocket multiplexer — bidirectional logical channels over a single WebSocket.

Uses the h2 library (HTTP/2) for stream multiplexing and flow control.

The mux.Server acts as the h2 CLIENT (odd stream IDs 1, 3, 5, …): it opens
channels by sending HEADERS frames. The mux.Client acts as the h2 SERVER and
receives channels via RequestReceived events.

Transport: h2 binary frames are sent/received as WebSocket messages.

Channel lifecycle:
  open:  Server calls open_channel() with channel metadata as x-pf-meta header.
  data:  Both sides exchange DATA frames.
  close: Sender calls close(); receiver gets StreamEnded or ChannelError.
         Either side may trigger reset_stream() for abrupt termination.

Flow control is handled automatically by h2 (WINDOW_UPDATE frames).
"""

import abc
import asyncio
import dataclasses
import json
import logging
import typing

import fastapi.websockets
import h2.config
import h2.connection
import h2.events
import h2.exceptions
import websockets.asyncio.client

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


def _meta_from_headers(headers: typing.Any) -> dict[str, typing.Any]:
    """Extract channel metadata from h2 request headers."""
    for name, value in headers:
        if name == "x-pf-meta":
            try:
                return json.loads(value)  # type: ignore[arg-type]
            except Exception:
                return {}
    return {}


class _Ws(abc.ABC):
    """Abstract WebSocket wrapper — hides FastAPI vs websockets library differences."""

    @abc.abstractmethod
    async def send(self, data: bytes) -> None:
        """Send a binary frame."""

    @abc.abstractmethod
    async def recv(self) -> bytes:
        """Receive a binary frame. Raises MuxError if connection closes."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Close the WebSocket."""


class _FastApiWs(_Ws):
    """Wraps fastapi.WebSocket to the _Ws interface."""

    def __init__(self, ws: fastapi.websockets.WebSocket) -> None:
        self._ws = ws

    async def send(self, data: bytes) -> None:
        await self._ws.send_bytes(data)

    async def recv(self) -> bytes:
        return await self._ws.receive_bytes()

    async def close(self) -> None:
        await self._ws.close()


class _WebsocketsWs(_Ws):
    """Wraps websockets.asyncio.client.ClientConnection to the _Ws interface."""

    def __init__(self, ws: websockets.asyncio.client.ClientConnection) -> None:
        self._ws = ws

    async def send(self, data: bytes) -> None:
        await self._ws.send(data)

    async def recv(self) -> bytes:
        async for frame in self._ws:
            if isinstance(frame, bytes):
                return frame
        raise MuxError("WebSocket connection closed")

    async def close(self) -> None:
        await self._ws.close()


class Channel:
    """
    A logical bidirectional channel multiplexed over a single WebSocket.

    Do not instantiate directly — use Server.open_channel() or Client.accept_channel().
    """

    def __init__(
        self, stream_id: int, mux: "typing.Any", meta: dict[str, typing.Any] | None = None
    ) -> None:
        self.channel_id = str(stream_id)
        self.meta = meta or {}
        self._stream_id = stream_id
        self._mux = mux
        self._rx: asyncio.Queue[bytes | _Sentinel | object] = asyncio.Queue()
        self._send_closed = False

    async def send(self, payload: bytes) -> None:
        """
        Send a payload to the remote end on this channel.

        Blocks when the h2 flow control window is exhausted.

        Raises:
            ChannelError: if this channel is already closed.
            MuxError: if the WebSocket connection is lost.
        """
        if self._send_closed:
            raise ChannelError(f"Channel {self.channel_id} is already closed")
        if self._mux.is_closed:
            raise MuxError("WebSocket connection is closed")
        await self._mux.write_stream(self._stream_id, payload, end_stream=False)

    async def receive(self) -> bytes:
        """
        Receive the next payload sent by the remote end on this channel.

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
        """Send END_STREAM to the remote end and mark this channel as closed."""
        if self._send_closed:
            return
        self._send_closed = True
        try:
            await self._mux.write_stream(self._stream_id, b"", end_stream=True)
        except Exception:
            pass

    def inject(self, item: object) -> None:
        """Enqueue an item into the RX queue (non-blocking, best-effort)."""
        try:
            self._rx.put_nowait(item)
        except asyncio.QueueFull:
            pass


class _MuxBase(abc.ABC):
    """
    Shared h2-over-WebSocket base implementation for both client and server sides.

    Subclasses override _handle_event to dispatch events specific to their role.
    """

    def __init__(self, ws: _Ws, client_side: bool) -> None:
        self._ws = ws
        self._h2 = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=client_side, header_encoding="utf-8")
        )
        self._h2.initiate_connection()
        self._cond: asyncio.Condition = asyncio.Condition()
        self._channels: dict[int, Channel] = {}
        self._closed: asyncio.Event = asyncio.Event()
        self._close_exc: Exception | None = None
        self._tasks: list[asyncio.Task[None]] = []

    @property
    def is_closed(self) -> bool:
        return self._closed.is_set()

    async def wait_closed(self) -> None:
        """Wait until the WebSocket connection is closed (by either side)."""
        await self._closed.wait()

    async def write_stream(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        """
        Send data on a stream, respecting h2 flow control and max frame size.

        Waits (under the condition) when the flow control window is exhausted.
        """
        remaining = data
        while True:
            outdata = b""
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

    async def close(self) -> None:
        """Gracefully shut down the mux."""
        if self._closed.is_set():
            return

        for ch in list(self._channels.values()):
            await ch.close()

        outdata = b""
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

    async def _reader(self) -> None:
        """Read and dispatch incoming h2 frames."""
        # Flush the preface generated by initiate_connection().
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
            while True:
                data = await self._ws.recv()
                outdata = b""
                async with self._cond:
                    events = self._h2.receive_data(data)
                    for event in events:
                        self._handle_event(event)
                    self._cond.notify_all()
                    outdata = self._h2.data_to_send()
                if outdata:
                    await self._ws.send(outdata)
        except Exception as exc:
            exc_out = exc
            logger.debug("Mux reader terminated: %s", exc)
        await self._fail(exc_out)

    @abc.abstractmethod
    def _handle_event(self, event: h2.events.Event) -> None:
        """Dispatch a single h2 event. Must be called under self._cond."""

    async def _fail(self, exc: Exception) -> None:
        """Handle a fatal error: mark closed, unblock all channels."""
        if self._closed.is_set():
            return
        self._closed.set()
        self._close_exc = exc

        sentinel = _Sentinel(exc=exc)
        async with self._cond:
            for ch in self._channels.values():
                ch.inject(sentinel)
            self._channels.clear()
            self._cond.notify_all()

        for t in self._tasks:
            t.cancel()


class Server(_MuxBase):
    """
    Server-side h2 multiplexer (h2 client role).

    Opens logical channels by sending HEADERS frames (stream IDs 1, 3, 5, …).
    The remote agent (Client) receives them via RequestReceived events.
    """

    def __init__(self, ws: fastapi.websockets.WebSocket) -> None:
        super().__init__(_FastApiWs(ws), client_side=True)
        self._tasks = [
            asyncio.create_task(self._reader(), name="mux-reader"),
        ]

    async def open_channel(self, meta: dict[str, typing.Any] | None = None) -> Channel:
        """
        Open a new logical channel and notify the remote end.

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
            await self._ws.send(outdata)

        logger.debug("Opened channel (stream_id=%d)", stream_id)
        return channel

    def _handle_event(self, event: h2.events.Event) -> None:
        """Dispatch a single h2 event. Must be called under self._cond."""
        if isinstance(event, h2.events.DataReceived):
            ch = self._channels.get(event.stream_id)
            if ch and event.data:
                ch.inject(event.data)
            self._h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            if event.stream_ended:
                if ch:
                    ch.inject(_STREAM_ENDED)
                self._channels.pop(event.stream_id, None)

        elif isinstance(event, h2.events.StreamEnded):
            ch = self._channels.pop(event.stream_id, None)
            if ch:
                ch.inject(_STREAM_ENDED)

        elif isinstance(event, h2.events.StreamReset):
            ch = self._channels.pop(event.stream_id, None)
            if ch:
                ch.inject(_Sentinel(exc=ChannelError(f"Stream {event.stream_id} reset by remote")))

        elif isinstance(event, h2.events.WindowUpdated):
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
            pass

        else:
            logger.debug("Mux: unhandled h2 event %r", event)


class Client(_MuxBase):
    """
    Client-side h2 multiplexer (h2 server role).

    Receives logical channels opened by Server via RequestReceived events
    and exposes them via accept_channel().
    """

    def __init__(self, ws: websockets.asyncio.client.ClientConnection) -> None:
        super().__init__(_WebsocketsWs(ws), client_side=False)
        self._open_queue: asyncio.Queue[Channel | object] = asyncio.Queue()
        self._tasks = [
            asyncio.create_task(self._reader(), name="demux-reader"),
        ]

    async def accept_channel(self) -> Channel:
        """
        Wait for the remote end to open a new logical channel and return it.

        Raises MuxError if the connection is closed before a channel arrives.
        """
        item = await self._open_queue.get()
        if item is _CLOSED:
            self._open_queue.put_nowait(_CLOSED)
            raise MuxError("WebSocket connection is closed")
        assert isinstance(item, Channel)
        return item

    def _handle_event(self, event: h2.events.Event) -> None:
        """Dispatch a single h2 event. Must be called under self._cond."""
        if isinstance(event, h2.events.RequestReceived):
            stream_id = event.stream_id
            meta = _meta_from_headers(event.headers)
            # Accept the CONNECT tunnel by sending 200 response headers.
            self._h2.send_headers(stream_id, [(":status", "200")])
            channel = Channel(stream_id, self, meta)
            self._channels[stream_id] = channel
            self._open_queue.put_nowait(channel)
            logger.debug("Demux: accepted channel (stream_id=%d)", stream_id)

        elif isinstance(event, h2.events.DataReceived):
            ch = self._channels.get(event.stream_id)
            if ch and event.data:
                ch.inject(event.data)
            self._h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            if event.stream_ended:
                if ch:
                    ch.inject(_STREAM_ENDED)
                self._channels.pop(event.stream_id, None)

        elif isinstance(event, h2.events.StreamEnded):
            ch = self._channels.pop(event.stream_id, None)
            if ch:
                ch.inject(_STREAM_ENDED)

        elif isinstance(event, h2.events.StreamReset):
            ch = self._channels.pop(event.stream_id, None)
            if ch:
                ch.inject(_Sentinel(exc=ChannelError(f"Stream {event.stream_id} reset by remote")))

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
        await super()._fail(exc)
        self._open_queue.put_nowait(_CLOSED)


_CLOSED: typing.Any = object()  # pushed into _open_queue to unblock accept_channel()
