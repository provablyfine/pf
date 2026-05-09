"""
Channel multiplexer. The multiplexing protocol is based on RFC 4254.
Removed channel_type field because we did not use it.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import enum
import struct
import typing

from .. import log
from . import exceptions, sockets


def _unpack_uint32(data: bytes, offset: int) -> tuple[int, int]:
    (value,) = struct.unpack_from("!I", data, offset)
    return value, offset + 4


def _unpack_string(data: bytes, offset: int) -> tuple[bytes, int]:
    length, offset = _unpack_uint32(data, offset)
    return data[offset : offset + length], offset + length


INITIAL_WINDOW = 1_048_576
MAX_PACKET = 32_768


@enum.unique
class ChannelMsg(enum.IntEnum):
    OPEN = 90
    OPEN_CONFIRMATION = 91
    OPEN_FAILURE = 92
    WINDOW_ADJUST = 93
    DATA = 94
    EOF = 96
    CLOSE = 97


@dataclasses.dataclass
class ChannelSnapshot:
    local_id: int
    remote_id: int
    recv_queue: list[bytes]  # b"" items are EOF sentinels
    send_window: int
    write_closed: bool
    read_closed: bool
    close_sent: bool

    def to_dict(self) -> dict[str, object]:
        """Serialize to dict (recv_queue items as base64)."""
        return {
            "local_id": self.local_id,
            "remote_id": self.remote_id,
            "recv_queue": [base64.b64encode(b).decode() for b in self.recv_queue],
            "send_window": self.send_window,
            "write_closed": self.write_closed,
            "read_closed": self.read_closed,
            "close_sent": self.close_sent,
        }

    @classmethod
    def from_dict(cls, d: dict[str, typing.Any]) -> ChannelSnapshot:
        """Deserialize from dict."""
        return cls(
            local_id=int(d["local_id"]),
            remote_id=int(d["remote_id"]),
            recv_queue=[base64.b64decode(s) for s in d["recv_queue"]],
            send_window=int(d["send_window"]),
            write_closed=bool(d["write_closed"]),
            read_closed=bool(d["read_closed"]),
            close_sent=bool(d["close_sent"]),
        )


@dataclasses.dataclass
class MuxSnapshot:
    socket_name: str
    next_id: int
    channels: list[ChannelSnapshot]
    pending_open: list[int]  # local_ids of channels awaiting channel_accept()

    def to_dict(self) -> dict[str, object]:
        """Serialize to dict."""
        return {
            "socket_name": self.socket_name,
            "next_id": self.next_id,
            "channels": [ch.to_dict() for ch in self.channels],
            "pending_open": self.pending_open,
        }

    @classmethod
    def from_dict(cls, d: dict[str, typing.Any]) -> MuxSnapshot:
        """Deserialize from dict."""
        return cls(
            socket_name=str(d["socket_name"]),
            next_id=int(d["next_id"]),
            channels=[ChannelSnapshot.from_dict(ch) for ch in d["channels"]],
            pending_open=list(d["pending_open"]),
        )


@dataclasses.dataclass
class Channel:
    local_id: int
    remote_id: int
    recv_queue: asyncio.Queue[bytes]
    send_window: int
    send_window_event: asyncio.Event
    write_closed: bool
    read_closed: bool
    close_sent: bool

    @classmethod
    def create(cls, local_id: int, remote_id: int, initial_window: int) -> Channel:
        ch = Channel(
            local_id,
            remote_id,
            recv_queue=asyncio.Queue[bytes](),
            send_window=0,
            send_window_event=asyncio.Event(),
            write_closed=False,
            read_closed=False,
            close_sent=False,
        )
        ch.send_window = initial_window
        if initial_window > 0:
            ch.send_window_event.set()
        return ch

    @classmethod
    def from_snapshot(cls, snap: ChannelSnapshot) -> Channel:
        ch = cls.create(snap.local_id, snap.remote_id, snap.send_window)
        for item in snap.recv_queue:
            ch.recv_queue.put_nowait(item)
        ch.write_closed = snap.write_closed
        ch.read_closed = snap.read_closed
        ch.close_sent = snap.close_sent
        return ch

    def to_snapshot(self) -> ChannelSnapshot:
        items: list[bytes] = []
        while not self.recv_queue.empty():
            items.append(self.recv_queue.get_nowait())
        return ChannelSnapshot(
            local_id=self.local_id,
            remote_id=self.remote_id,
            recv_queue=items,
            send_window=self.send_window,
            write_closed=self.write_closed,
            read_closed=self.read_closed,
            close_sent=self.close_sent,
        )


class Mux:
    def __init__(
        self,
        socket_name: str,
        channels: dict[int, Channel],
        next_id: int,
        pending_open: asyncio.Queue[int],
    ) -> None:
        sock = sockets.store.get(socket_name)
        if sock is None:
            raise exceptions.Error(f"Socket '{socket_name}' not found in store")
        self._socket_name = socket_name
        self._sock = sock
        self._channels = channels
        self._next_id = next_id
        self._pending_open = pending_open
        self._open_results: dict[int, asyncio.Future[int]] = {}
        self._write_lock = asyncio.Lock()
        self._reader_task = asyncio.create_task(self._reader_loop())
        def _done_cb(fut: asyncio.Future[None]) -> None:
            if fut.cancelled():
                # If the process is being killed for good, we do not need to cleanup sockets
                # If the process is dying to reload, we need to keep sockets around so they
                # can be restored later.
                return
            sockets.store.remove(self._socket_name)
            self._sock.close()
        self._reader_task.add_done_callback(_done_cb)

    @classmethod
    def create(cls, socket_name: str) -> Mux:
        """Create a fresh Mux backed by the named socket."""
        return cls(socket_name, {}, 0, asyncio.Queue[int]())

    def add_rx_done_callback(self, callback: typing.Callable[[asyncio.Future[None]], typing.Any]):
        self._reader_task.add_done_callback(callback)

    def stop(self) -> None:
        """Stop reader task."""
        self._reader_task.cancel()

    async def wait_stop(self) -> None:
        """Wait until reader task exits (remote disconnected or closed)."""
        try:
            await self._reader_task
        except asyncio.CancelledError:
            # task already cancelled
            pass

    def close_socket(self) -> None:
        """Close underlying socket."""
        self._sock.close()

    def snapshot(self) -> MuxSnapshot:
        """Snapshot all mux state."""
        assert self._reader_task.done()
        channels = [ch.to_snapshot() for ch in self._channels.values()]

        pending_open: list[int] = []
        while not self._pending_open.empty():
            pending_open.append(self._pending_open.get_nowait())

        return MuxSnapshot(
            socket_name=self._socket_name,
            next_id=self._next_id,
            channels=channels,
            pending_open=pending_open,
        )

    @classmethod
    def restore(cls, snap: MuxSnapshot) -> Mux:
        """Restore a Mux from a snapshot."""
        channels = {s.local_id: Channel.from_snapshot(s) for s in snap.channels}
        pending_open = asyncio.Queue[int]()
        for local_id in snap.pending_open:
            pending_open.put_nowait(local_id)
        return Mux(snap.socket_name, channels, snap.next_id, pending_open)

    async def channel_accept(self) -> int:
        """Accept next incoming channel from peer. Returns local_id."""

        get_task = asyncio.create_task(self._pending_open.get())

        assert self._reader_task is not None

        done, _ = await asyncio.wait(
            [get_task, self._reader_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        if self._reader_task in done:
            get_task.cancel()
            raise exceptions.Error("Multiplexer connection closed")

        return await get_task

    async def channel_open(self) -> int:
        """Open a channel. Returns local_id."""
        local_id = self._next_id
        self._next_id += 1

        future: asyncio.Future[int] = asyncio.Future()
        self._open_results[local_id] = future

        await self._send_channel_open(local_id, INITIAL_WINDOW, MAX_PACKET)
        return await future

    async def channel_read(self, local_id: int) -> bytes:
        """Read data from channel. Returns b'' on EOF."""
        ch = self._channels[local_id]
        if ch.read_closed:
            return b""
        data = await ch.recv_queue.get()
        if data == b"":  # EOF sentinel
            ch.read_closed = True
        return data

    async def channel_write(self, local_id: int, data: bytes) -> None:
        """Write data to channel, respecting send window."""
        ch = self._channels[local_id]
        if ch.write_closed:
            raise exceptions.Error("Channel write closed")

        offset = 0
        while offset < len(data):
            while ch.send_window == 0:
                ch.send_window_event.clear()
                await ch.send_window_event.wait()

            chunk_size = min(MAX_PACKET, ch.send_window, len(data) - offset)
            chunk = data[offset : offset + chunk_size]
            await self._send_channel_data(ch.remote_id, chunk)
            ch.send_window -= chunk_size
            offset += chunk_size

    async def channel_close_write(self, local_id: int) -> None:
        """Half-close write side. Peer receives EOF, but can still send."""
        ch = self._channels[local_id]
        if ch.write_closed:
            return
        ch.write_closed = True
        await self._send_channel_eof(ch.remote_id)

    async def channel_close(self, local_id: int) -> None:
        """Close channel fully."""
        ch = self._channels[local_id]
        if ch.close_sent:
            return
        ch.close_sent = True
        if not ch.write_closed:
            ch.write_closed = True
            await self._send_channel_eof(ch.remote_id)
        await self._send_channel_close(ch.remote_id)

    async def _reader_loop(self) -> None:
        """Background task reading packets from socket.

        Dispatch is shielded from cancellation: if the task is cancelled while
        dispatching a packet, the dispatch runs to completion before the
        CancelledError propagates. This ensures mux state stays coherent for
        snapshot() regardless of when stop() is called.
        """
        try:
            while True:
                packet = await self._read_packet()
                if not packet:
                    break
                dispatch_task: asyncio.Task[None] = asyncio.ensure_future(self._dispatch_packet(packet))
                try:
                    await asyncio.shield(dispatch_task)
                except asyncio.CancelledError:
                    await dispatch_task  # let dispatch finish before propagating
                    raise
        except Exception as e:
            error = exceptions.Error(f"Channel multiplexer reader failed: {e}")
            for _, future in list(self._open_results.items()):
                if not future.done():
                    future.set_exception(error)
            for local_id in list(self._channels):
                await self._recv_eof(local_id)

    async def _read_n(self, n: int) -> bytes:
        buffer: bytes = b""
        while len(buffer) < n:
            chunk = await self._sock.recv(n - len(buffer))
            if not chunk:
                return b""
            buffer += chunk
        return buffer

    async def _read_packet(self) -> bytes:
        """Read a framed packet (uint32 length + payload)."""
        chunk = await self._read_n(4)
        if len(chunk) == 0:
            return b""
        length = int.from_bytes(chunk, byteorder="big")
        packet = await self._read_n(length)
        return packet

    async def _write_packet(self, packet: bytes) -> None:
        """Write a framed packet."""
        async with self._write_lock:
            length = len(packet).to_bytes(4, byteorder="big")
            await self._sock.send(length + packet)

    async def _dispatch_packet(self, packet: bytes) -> None:
        if not packet:
            return
        msg_type = packet[0]

        if msg_type == ChannelMsg.OPEN:
            await self._handle_channel_open(packet)
        elif msg_type == ChannelMsg.OPEN_CONFIRMATION:
            await self._handle_channel_open_confirmation(packet)
        elif msg_type == ChannelMsg.OPEN_FAILURE:
            await self._handle_channel_open_failure(packet)
        elif msg_type == ChannelMsg.DATA:
            await self._handle_channel_data(packet)
        elif msg_type == ChannelMsg.WINDOW_ADJUST:
            await self._handle_window_adjust(packet)
        elif msg_type == ChannelMsg.EOF:
            await self._handle_eof(packet)
        elif msg_type == ChannelMsg.CLOSE:
            await self._handle_close(packet)

    async def _handle_channel_open(self, packet: bytes) -> None:
        sender_channel, offset = _unpack_uint32(packet, 1)
        initial_window, _ = _unpack_uint32(packet, offset)

        local_id = self._next_id
        self._next_id += 1

        self._channels[local_id] = Channel.create(local_id, sender_channel, initial_window)

        await self._send_channel_open_confirmation(local_id, sender_channel, INITIAL_WINDOW, MAX_PACKET)
        await self._pending_open.put(local_id)

    async def _handle_channel_open_confirmation(self, packet: bytes) -> None:
        recipient_channel, offset = _unpack_uint32(packet, 1)
        sender_channel, offset = _unpack_uint32(packet, offset)
        initial_window, _ = _unpack_uint32(packet, offset)

        if recipient_channel not in self._open_results:
            return

        future = self._open_results.pop(recipient_channel)
        self._channels[recipient_channel] = Channel.create(recipient_channel, sender_channel, initial_window)
        future.set_result(recipient_channel)

    async def _handle_channel_open_failure(self, packet: bytes) -> None:
        recipient_channel, offset = _unpack_uint32(packet, 1)
        _, offset = _unpack_uint32(packet, offset)  # reason
        description, _ = _unpack_string(packet, offset)

        if recipient_channel not in self._open_results:
            return

        future = self._open_results.pop(recipient_channel)
        future.set_exception(exceptions.Error(f"Channel open failed: {description.decode()}"))

    async def _handle_channel_data(self, packet: bytes) -> None:
        recipient_channel, offset = _unpack_uint32(packet, 1)
        data, _ = _unpack_string(packet, offset)

        if recipient_channel not in self._channels:
            return

        await self._recv_data(recipient_channel, data)
        await self._send_window_adjust(recipient_channel, len(data))

    async def _handle_window_adjust(self, packet: bytes) -> None:
        recipient_channel, offset = _unpack_uint32(packet, 1)
        bytes_to_add, _ = _unpack_uint32(packet, offset)

        if recipient_channel not in self._channels:
            return

        self._recv_window_adjust(recipient_channel, bytes_to_add)

    async def _handle_eof(self, packet: bytes) -> None:
        recipient_channel, _ = _unpack_uint32(packet, 1)

        if recipient_channel not in self._channels:
            return

        await self._recv_eof(recipient_channel)

    async def _handle_close(self, packet: bytes) -> None:
        recipient_channel, _ = _unpack_uint32(packet, 1)

        if recipient_channel in self._channels:
            await self._recv_close(recipient_channel)

    async def _recv_data(self, local_id: int, data: bytes) -> None:
        await self._channels[local_id].recv_queue.put(data)

    async def _recv_eof(self, local_id: int) -> None:
        ch = self._channels[local_id]
        if not ch.read_closed:
            await ch.recv_queue.put(b"")

    async def _recv_close(self, local_id: int) -> None:
        await self._recv_eof(local_id)
        ch = self._channels[local_id]
        if not ch.close_sent:
            ch.close_sent = True
            await self._send_channel_close(ch.remote_id)

    def _recv_window_adjust(self, local_id: int, bytes_to_add: int) -> None:
        ch = self._channels[local_id]
        ch.send_window += bytes_to_add
        if ch.send_window > 0:
            ch.send_window_event.set()

    async def _send_channel_open_confirmation(
        self, local_id: int, remote_id: int, initial_window: int, max_packet: int
    ) -> None:
        packet = struct.pack("!BIIII", ChannelMsg.OPEN_CONFIRMATION, remote_id, local_id, initial_window, max_packet)
        await self._write_packet(packet)

    async def _send_channel_data(self, recipient_channel: int, data: bytes) -> None:
        packet = struct.pack("!BII", ChannelMsg.DATA, recipient_channel, len(data)) + data
        await self._write_packet(packet)

    async def _send_window_adjust(self, recipient_channel: int, bytes_to_add: int) -> None:
        packet = struct.pack("!BII", ChannelMsg.WINDOW_ADJUST, recipient_channel, bytes_to_add)
        await self._write_packet(packet)

    async def _send_channel_eof(self, recipient_channel: int) -> None:
        packet = struct.pack("!BI", ChannelMsg.EOF, recipient_channel)
        await self._write_packet(packet)

    async def _send_channel_close(self, recipient_channel: int) -> None:
        packet = struct.pack("!BI", ChannelMsg.CLOSE, recipient_channel)
        await self._write_packet(packet)

    async def _send_channel_open(self, local_id: int, initial_window: int, max_packet: int) -> None:
        packet = struct.pack("!BIII", ChannelMsg.OPEN, local_id, initial_window, max_packet)
        await self._write_packet(packet)
