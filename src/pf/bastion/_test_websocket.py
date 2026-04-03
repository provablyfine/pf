"""
Test helper — create a pair of connected WebSocket instance for testing mux.Server.

Uses socket pair with asyncio streams, implementing minimal WebSocket framing.
"""

import asyncio
import base64
import json
import socket
import struct

FIN = 0x80
TEXT = 0x01
CLOSE = 0x08

FIN = 0x80
TEXT = 0x01
CLOSE = 0x08
MASK = 0x20


def _make_frame(opcode: int, payload: bytes, masked: bool = False) -> bytes:
    length = len(payload)
    header = bytes([FIN | opcode])
    if length < 126:
        header += bytes([(0x80 if masked else 0) | length])
    elif length < 65536:
        header += bytes([(0x80 if masked else 0) | 126, (length >> 8) & 0xFF, length & 0xFF])
    else:
        header += bytes([(0x80 if masked else 0) | 127, *struct.pack(">Q", length)])
    if masked:
        mask = bytes([0x00, 0x00, 0x00, 0x00])
        mask_extended = bytes(mask * ((len(payload) + 3) // 4))[: len(payload)]
        payload = bytes(a ^ b for a, b in zip(payload, mask_extended))
        header += mask
    return header + payload


def _parse_frame(data: bytes) -> tuple[int, bytes, bool]:
    if len(data) < 2:
        return 0, b"", False
    first = data[0]
    second = data[1]
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    offset = 2
    if length == 126:
        if len(data) < 4:
            return 0, b"", False
        length = struct.unpack(">H", data[2:4])[0]
        offset = 4
    elif length == 127:
        if len(data) < 10:
            return 0, b"", False
        length = struct.unpack(">Q", data[2:10])[0]
        offset = 10
    if masked:
        mask = data[offset : offset + 4]
        offset += 4
    else:
        mask = None
    if len(data) < offset + length:
        return 0, b"", False
    payload = data[offset : offset + length]
    if masked and mask:
        mask_extended = bytes(mask * ((len(payload) + 3) // 4))[: len(payload)]
        payload = bytes(a ^ b for a, b in zip(payload, mask_extended))
    return opcode, payload, masked


class MockWebSocket:
    """
    A WebSocket-like object using a socket pair with proper framing.

    This implements the minimal interface needed by mux.Server:
    - send_json(msg)
    - receive_json()
    - close()
    """

    def __init__(self, sock: socket.socket, is_server: bool = True):
        self._sock = sock
        self._sock.setblocking(False)
        self._is_server = is_server
        self._closed = False
        self._buffer = b""
        self._out_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._loop = asyncio.get_event_loop()
        self._reader_task = self._loop.create_task(self._reader())

    async def _reader(self) -> None:
        while not self._closed:
            try:
                data = self._sock.recv(4096)
                if not data:
                    break
                self._buffer += data
                while self._buffer:
                    opcode, payload, masked = _parse_frame(self._buffer)
                    if opcode == 0:
                        break
                    header_len = 2
                    second = self._buffer[1] if len(self._buffer) > 1 else 0
                    length = second & 0x7F
                    if length == 126:
                        header_len = 4
                    elif length == 127:
                        header_len = 10
                    if masked:
                        header_len += 4
                    frame_len = header_len + len(payload)
                    self._buffer = self._buffer[frame_len:]
                    if opcode == CLOSE:
                        self._closed = True
                        break
                    if opcode == TEXT:
                        await self._out_queue.put(payload)
            except BlockingIOError:
                await asyncio.sleep(0.01)
            except Exception:
                break

    async def send_json(self, msg: dict | list) -> None:
        if self._closed:
            raise ConnectionResetError("WebSocket closed")
        msg = dict(msg)
        if msg.get("type") == "data" and "payload" in msg:
            payload = msg["payload"]
            if isinstance(payload, str):
                try:
                    base64.b64decode(payload.encode("ascii"))
                except Exception:
                    payload = base64.b64encode(payload.encode("utf-8")).decode("ascii")
            elif isinstance(payload, bytes):
                payload = base64.b64encode(payload).decode("ascii")
            msg["payload"] = payload
        data = json.dumps(msg).encode("utf-8")
        frame = _make_frame(TEXT, data, masked=not self._is_server)
        self._sock.sendall(frame)

    async def receive_json(self) -> dict | list:
        if self._closed:
            raise ConnectionResetError("WebSocket closed")
        try:
            payload = await asyncio.wait_for(self._out_queue.get(), timeout=1.0)
            return json.loads(payload)
        except TimeoutError:
            raise ConnectionResetError("WebSocket closed")

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            frame = _make_frame(CLOSE, b"", masked=not self._is_server)
            self._sock.sendall(frame)
        except Exception:
            pass
        self._reader_task.cancel()

    @property
    def is_closed(self) -> bool:
        return self._closed


def create_websocket_pair() -> tuple[MockWebSocket, MockWebSocket]:
    """
    Create a pair of connected WebSocket instances using a socket pair.

    Returns:
        (server_ws, client_ws): Two WebSocket instances connected bidirectionally.
    """
    s1, s2 = socket.socketpair()
    server = MockWebSocket(s1, is_server=True)
    client = MockWebSocket(s2, is_server=False)
    return server, client


# ---------------------------------------------------------------------------
# Queue-backed mock pair for testing demux.Client
# ---------------------------------------------------------------------------


class _Pipe:
    """One-directional channel between two mock WebSocket sides."""

    def __init__(self) -> None:
        self._q: asyncio.Queue[str | None] = asyncio.Queue()

    async def put(self, item: str) -> None:
        await self._q.put(item)

    async def get(self) -> str | None:
        return await self._q.get()

    def close(self) -> None:
        """Signal EOF to the reader."""
        self._q.put_nowait(None)


class MockServerSide:
    """
    Simulates the mux.Server's WebSocket view for use in test_demux.py.

    Implements the send_json / receive_json interface so tests can drive the
    server side of the protocol without a real network connection.
    """

    def __init__(self, to_client: "_Pipe", from_client: "_Pipe") -> None:
        self._to = to_client
        self._from = from_client
        self._closed = False

    async def send_json(self, msg: dict) -> None:
        if self._closed:
            raise ConnectionResetError("closed")
        await self._to.put(json.dumps(msg))

    async def receive_json(self) -> dict:
        raw = await self._from.get()
        if raw is None:
            raise ConnectionResetError("closed")
        return json.loads(raw)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._to.close()
        self._from.close()

    @property
    def is_closed(self) -> bool:
        return self._closed


class MockClientWebSocket:
    """
    Simulates the websockets.ClientConnection view for use in test_demux.py.

    Implements send(str) and async iteration so demux.Client can be constructed
    around it without a real WebSocket connection.
    """

    def __init__(self, from_server: "_Pipe", to_server: "_Pipe") -> None:
        self._from = from_server
        self._to = to_server
        self._closed = False

    async def send(self, data: str) -> None:
        await self._to.put(data)

    def __aiter__(self) -> "MockClientWebSocket":
        return self

    async def __anext__(self) -> str:
        raw = await self._from.get()
        if raw is None:
            raise StopAsyncIteration
        return raw

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._from.close()
        self._to.close()


def create_demux_pair() -> tuple[MockServerSide, MockClientWebSocket]:
    """
    Create a pair for testing demux.Client.

    Returns:
        (server, client_ws): server speaks send_json/receive_json;
                             client_ws speaks send/async-iteration.
    """
    to_client = _Pipe()
    from_client = _Pipe()
    return MockServerSide(to_client, from_client), MockClientWebSocket(to_client, from_client)
