"""
Test helper — create connected WebSocket instances for testing mux.Server
and demux.Client.

Uses asyncio streams over a socket pair with minimal WebSocket binary framing.
Frames are always binary (opcode 0x02) since h2 is a binary protocol.
"""

import asyncio
import socket
import struct

FIN = 0x80
BINARY = 0x02
CLOSE = 0x08


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
        mask = b"\x00\x00\x00\x00"
        mask_ext = (mask * ((len(payload) + 3) // 4))[: len(payload)]
        payload = bytes(a ^ b for a, b in zip(payload, mask_ext))
        header += mask
    return header + payload


class _BinaryWebSocket:
    """
    A WebSocket-like object backed by asyncio StreamReader/StreamWriter.
    Uses binary frames only (h2 is a binary protocol).

    Implements both interfaces:
        send_bytes / receive_bytes  — for mux.Server (FastAPI-style)
        send / __aiter__            — for demux.Client (websockets-style)
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        masked: bool = False,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._masked = masked
        self._closed = False
        self._rx: asyncio.Queue[bytes] = asyncio.Queue()
        loop = asyncio.get_event_loop()
        self._read_task = loop.create_task(self._read_loop())

    async def _read_frame(self) -> tuple[int, bytes]:
        """Read one WebSocket frame and return (opcode, payload)."""
        header = await self._reader.readexactly(2)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F

        if length == 126:
            ext = await self._reader.readexactly(2)
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = await self._reader.readexactly(8)
            length = struct.unpack(">Q", ext)[0]

        if masked:
            mask = await self._reader.readexactly(4)
        else:
            mask = None

        payload = await self._reader.readexactly(length)

        if masked and mask:
            mask_ext = (mask * ((len(payload) + 3) // 4))[: len(payload)]
            payload = bytes(a ^ b for a, b in zip(payload, mask_ext))

        return opcode, payload

    async def _read_loop(self) -> None:
        try:
            while not self._closed:
                opcode, payload = await self._read_frame()
                if opcode == CLOSE:
                    self._closed = True
                    break
                if opcode == BINARY:
                    await self._rx.put(payload)
        except Exception:
            self._closed = True

    async def _write_frame(self, opcode: int, payload: bytes) -> None:
        frame = _make_frame(opcode, payload, masked=self._masked)
        self._writer.write(frame)
        await self._writer.drain()

    # FastAPI WebSocket interface (used by mux.Server)
    async def send_bytes(self, data: bytes) -> None:
        if self._closed:
            raise ConnectionResetError("WebSocket closed")
        await self._write_frame(BINARY, data)

    async def receive_bytes(self) -> bytes:
        if self._closed:
            raise ConnectionResetError("WebSocket closed")
        return await self._rx.get()

    # websockets-style interface (used by demux.Client)
    async def send(self, data: bytes) -> None:
        await self.send_bytes(data)

    def __aiter__(self) -> "_BinaryWebSocket":
        return self

    async def __anext__(self) -> bytes:
        if self._closed and self._rx.empty():
            raise StopAsyncIteration
        try:
            return await asyncio.wait_for(self._rx.get(), timeout=5.0)
        except TimeoutError:
            raise StopAsyncIteration

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._write_frame(CLOSE, b"")
        except Exception:
            pass
        self._read_task.cancel()
        self._writer.close()


async def create_ws_pair() -> tuple["_BinaryWebSocket", "_BinaryWebSocket"]:
    """
    Create a pair of connected binary WebSocket instances via a socket pair.

    Returns:
        (server_ws, client_ws): server does not mask; client masks frames.
    """
    s1, s2 = socket.socketpair()
    r1, w1 = await asyncio.open_connection(sock=s1)
    r2, w2 = await asyncio.open_connection(sock=s2)
    server_ws = _BinaryWebSocket(r1, w1, masked=False)
    client_ws = _BinaryWebSocket(r2, w2, masked=True)
    return server_ws, client_ws
