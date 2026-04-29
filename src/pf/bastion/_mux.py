"""Internal SSH channel multiplexer (RFC4254)."""

from __future__ import annotations

import asyncio
import enum
import struct

from .. import anet
from . import exceptions


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


class ChannelImpl:
    """Internal SSH channel state. Used by Mux."""

    def __init__(
        self,
        local_id: int,
        remote_id: int,
        channel_type: str,
        mux: Mux,
        initial_window: int,
    ) -> None:
        self._local_id = local_id
        self._remote_id = remote_id
        self._channel_type = channel_type
        self._mux = mux
        self._recv_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._send_window = initial_window
        self._send_window_event = asyncio.Event()
        if initial_window > 0:
            self._send_window_event.set()
        self._write_closed = False  # EOF sent to remote (close_write or close)
        self._read_closed = False  # EOF received from remote
        self._close_sent = False  # CLOSE sent to remote

    @property
    def channel_type(self) -> str:
        return self._channel_type

    async def read(self) -> bytes:
        """Read data from channel. Returns b'' on EOF."""
        if self._read_closed:
            return b""
        data = await self._recv_queue.get()
        if data == b"":  # EOF sentinel
            self._read_closed = True
        return data

    async def write(self, data: bytes) -> None:
        """Write data to channel, respecting send window."""
        if self._write_closed:
            raise exceptions.Error("Channel write closed")

        offset = 0
        while offset < len(data):
            # Wait for send window
            while self._send_window == 0:
                self._send_window_event.clear()
                await self._send_window_event.wait()

            # Send up to MAX_PACKET or available window
            chunk_size = min(MAX_PACKET, self._send_window, len(data) - offset)
            chunk = data[offset : offset + chunk_size]
            await self._mux.send_channel_data(self._remote_id, chunk)
            self._send_window -= chunk_size
            offset += chunk_size

    async def close_write(self) -> None:
        """Half-close: stop sending, peer will receive EOF. Still readable."""
        if self._write_closed:
            return
        self._write_closed = True
        await self._mux.send_channel_eof(self._remote_id)

    async def close(self) -> None:
        """Close channel fully."""
        if self._close_sent:
            return
        self._close_sent = True
        if not self._write_closed:
            self._write_closed = True
            await self._mux.send_channel_eof(self._remote_id)
        await self._mux.send_channel_close(self._remote_id)

    async def recv_data(self, data: bytes) -> None:
        """Mux callback: push data to recv queue."""
        await self._recv_queue.put(data)

    async def recv_eof(self) -> None:
        """Mux callback: signal EOF from peer (idempotent)."""
        if not self._read_closed:
            await self._recv_queue.put(b"")

    async def recv_close(self) -> None:
        """Mux callback: peer sent CLOSE. Signal EOF, reply with CLOSE if needed."""
        await self.recv_eof()
        if not self._close_sent:
            self._close_sent = True
            await self._mux.send_channel_close(self._remote_id)

    def recv_window_adjust(self, bytes_to_add: int) -> None:
        """Mux callback: increase send window."""
        self._send_window += bytes_to_add
        if self._send_window > 0:
            self._send_window_event.set()


class Mux:
    """SSH channel multiplexer."""

    def __init__(self, sock: anet.base.Socket) -> None:
        self._sock = sock
        self._channels: dict[int, ChannelImpl] = {}
        self._next_id = 0
        self._pending_open: asyncio.Queue[ChannelImpl] = asyncio.Queue()
        self._open_results: dict[int, tuple[str, asyncio.Future[ChannelImpl]]] = {}
        self._write_lock = asyncio.Lock()
        self._reader_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start background reader task."""
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(self._reader_loop())

    async def stop(self) -> None:
        """Stop reader task."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

    async def wait_closed(self) -> None:
        """Wait until reader task exits (remote disconnected or closed)."""
        await self.start()
        if self._reader_task is not None:
            await self._reader_task

    async def close_socket(self) -> None:
        """Close underlying socket."""
        await self._sock.close()

    async def accept(self) -> ChannelImpl:
        """Accept next incoming channel from peer."""
        await self.start()
        return await self._pending_open.get()

    async def open_channel(self, channel_type: str) -> ChannelImpl:
        """Open a channel of given type."""
        await self.start()

        local_id = self._next_id
        self._next_id += 1

        future: asyncio.Future[ChannelImpl] = asyncio.Future()
        self._open_results[local_id] = (channel_type, future)

        await self._send_channel_open(local_id, channel_type, INITIAL_WINDOW, MAX_PACKET)
        return await future

    async def _reader_loop(self) -> None:
        """Background task reading packets from socket."""
        try:
            while True:
                packet = await self._read_packet()
                if not packet:
                    break
                await self._dispatch_packet(packet)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            error = exceptions.Error(f"Channel multiplexer reader failed: {e}")
            # Signal all pending channel opens
            for _, (_, future) in list(self._open_results.items()):
                if not future.done():
                    future.set_exception(error)
            # Signal all active channels with EOF
            for channel in list(self._channels.values()):
                await channel.recv_eof()

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
        """Dispatch packet by message type."""
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
        """Handle SSH_MSG_CHANNEL_OPEN."""
        channel_type, offset = _unpack_string(packet, 1)
        sender_channel, offset = _unpack_uint32(packet, offset)
        initial_window, _ = _unpack_uint32(packet, offset)

        local_id = self._next_id
        self._next_id += 1

        channel = ChannelImpl(local_id, sender_channel, channel_type.decode(), self, initial_window)
        self._channels[local_id] = channel

        await self._send_channel_open_confirmation(local_id, sender_channel, INITIAL_WINDOW, MAX_PACKET)
        await self._pending_open.put(channel)

    async def _handle_channel_open_confirmation(self, packet: bytes) -> None:
        """Handle SSH_MSG_CHANNEL_OPEN_CONFIRMATION."""
        recipient_channel, offset = _unpack_uint32(packet, 1)
        sender_channel, offset = _unpack_uint32(packet, offset)
        initial_window, _ = _unpack_uint32(packet, offset)

        if recipient_channel not in self._open_results:
            return

        channel_type, future = self._open_results.pop(recipient_channel)
        channel = ChannelImpl(recipient_channel, sender_channel, channel_type, self, initial_window)
        self._channels[recipient_channel] = channel
        future.set_result(channel)

    async def _handle_channel_open_failure(self, packet: bytes) -> None:
        """Handle SSH_MSG_CHANNEL_OPEN_FAILURE."""
        recipient_channel, offset = _unpack_uint32(packet, 1)
        _, offset = _unpack_uint32(packet, offset)  # reason
        description, offset = _unpack_string(packet, offset)

        if recipient_channel not in self._open_results:
            return

        _, future = self._open_results.pop(recipient_channel)
        future.set_exception(exceptions.Error(f"Channel open failed: {description.decode()}"))

    async def _handle_channel_data(self, packet: bytes) -> None:
        """Handle SSH_MSG_CHANNEL_DATA."""
        recipient_channel, offset = _unpack_uint32(packet, 1)
        data, _ = _unpack_string(packet, offset)

        if recipient_channel not in self._channels:
            return

        channel = self._channels[recipient_channel]
        await channel.recv_data(data)
        # Send window adjust to replenish
        await self._send_window_adjust(recipient_channel, len(data))

    async def _handle_window_adjust(self, packet: bytes) -> None:
        """Handle SSH_MSG_CHANNEL_WINDOW_ADJUST."""
        recipient_channel, offset = _unpack_uint32(packet, 1)
        bytes_to_add, _ = _unpack_uint32(packet, offset)

        if recipient_channel not in self._channels:
            return

        channel = self._channels[recipient_channel]
        channel.recv_window_adjust(bytes_to_add)

    async def _handle_eof(self, packet: bytes) -> None:
        """Handle SSH_MSG_CHANNEL_EOF."""
        recipient_channel, _ = _unpack_uint32(packet, 1)

        if recipient_channel not in self._channels:
            return

        channel = self._channels[recipient_channel]
        await channel.recv_eof()

    async def _handle_close(self, packet: bytes) -> None:
        """Handle SSH_MSG_CHANNEL_CLOSE."""
        recipient_channel, _ = _unpack_uint32(packet, 1)

        if recipient_channel in self._channels:
            channel = self._channels.pop(recipient_channel)
            await channel.recv_close()

    async def _send_channel_open_confirmation(
        self, local_id: int, remote_id: int, initial_window: int, max_packet: int
    ) -> None:
        """Send SSH_MSG_CHANNEL_OPEN_CONFIRMATION."""
        packet = struct.pack(
            "!BIIII", ChannelMsg.OPEN_CONFIRMATION, remote_id, local_id, initial_window, max_packet
        )
        await self._write_packet(packet)

    async def send_channel_data(self, recipient_channel: int, data: bytes) -> None:
        """Send SSH_MSG_CHANNEL_DATA."""
        packet = struct.pack("!BII", ChannelMsg.DATA, recipient_channel, len(data)) + data
        await self._write_packet(packet)

    async def _send_window_adjust(self, recipient_channel: int, bytes_to_add: int) -> None:
        """Send SSH_MSG_CHANNEL_WINDOW_ADJUST."""
        packet = struct.pack("!BII", ChannelMsg.WINDOW_ADJUST, recipient_channel, bytes_to_add)
        await self._write_packet(packet)

    async def send_channel_eof(self, recipient_channel: int) -> None:
        """Send SSH_MSG_CHANNEL_EOF."""
        packet = struct.pack("!BI", ChannelMsg.EOF, recipient_channel)
        await self._write_packet(packet)

    async def send_channel_close(self, recipient_channel: int) -> None:
        """Send SSH_MSG_CHANNEL_CLOSE."""
        packet = struct.pack("!BI", ChannelMsg.CLOSE, recipient_channel)
        await self._write_packet(packet)

    async def _send_channel_open(self, local_id: int, channel_type: str, initial_window: int, max_packet: int) -> None:
        """Send SSH_MSG_CHANNEL_OPEN."""
        channel_type_bytes = channel_type.encode()
        packet = (
            struct.pack("!BI", ChannelMsg.OPEN, len(channel_type_bytes))
            + channel_type_bytes
            + struct.pack("!III", local_id, initial_window, max_packet)
        )
        await self._write_packet(packet)
