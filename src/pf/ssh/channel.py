import asyncio

from . import buffer, constants, exceptions, tcp

INITIAL_WINDOW = 1_048_576
MAX_PACKET = 32_768


class Channel:
    """Represents an established SSH channel."""

    def __init__(
        self,
        local_id: int,
        remote_id: int,
        channel_type: str,
        mux: "_Mux",
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
        self._closed = False

    @property
    def channel_type(self) -> str:
        return self._channel_type

    async def read(self) -> bytes:
        """Read data from channel. Returns b'' on EOF."""
        if self._closed:
            return b""
        data = await self._recv_queue.get()
        if data == b"":  # EOF sentinel
            self._closed = True
        return data

    async def write(self, data: bytes) -> None:
        """Write data to channel, respecting send window."""
        if self._closed:
            raise exceptions.Error("Channel closed")

        offset = 0
        while offset < len(data):
            # Wait for send window
            while self._send_window == 0:
                self._send_window_event.clear()
                await self._send_window_event.wait()

            # Send up to MAX_PACKET or available window
            chunk_size = min(MAX_PACKET, self._send_window, len(data) - offset)
            chunk = data[offset : offset + chunk_size]
            await self._mux._send_channel_data(self._remote_id, chunk)  # type: ignore[reportPrivateUsage]
            self._send_window -= chunk_size
            offset += chunk_size

    async def close(self) -> None:
        """Close channel."""
        if self._closed:
            return
        self._closed = True
        await self._mux._send_channel_eof(self._remote_id)  # type: ignore[reportPrivateUsage]
        await self._mux._send_channel_close(self._remote_id)  # type: ignore[reportPrivateUsage]

    async def _recv_data(self, data: bytes) -> None:
        """Internal: push data to recv queue."""
        await self._recv_queue.put(data)

    async def _recv_eof(self) -> None:
        """Internal: signal EOF."""
        await self._recv_queue.put(b"")  # type: ignore[arg-type]

    def _recv_window_adjust(self, bytes_to_add: int) -> None:
        """Internal: increase send window."""
        self._send_window += bytes_to_add
        if self._send_window > 0:
            self._send_window_event.set()


class _Mux:
    """Multiplex SSH channels over a socket."""

    def __init__(self, sock: tcp.TcpSocket) -> None:
        self._sock = sock
        self._channels: dict[int, Channel] = {}
        self._next_id = 0
        self._pending_open: asyncio.Queue[Channel] = asyncio.Queue()
        self._open_results: dict[int, asyncio.Future[Channel]] = {}
        self._write_lock = asyncio.Lock()
        self._reader_task: asyncio.Task[None] | None = None

    async def _start(self) -> None:
        """Start background reader task."""
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(self._reader_loop())

    async def _stop(self) -> None:
        """Stop reader task."""
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

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
        except Exception:
            pass

    async def _read_n(self, n: int) -> bytes:
        buffer: bytes = b""
        while len(buffer) < n:
            try:
                chunk = await self._sock.recv(n-len(buffer))
            except TimeoutError:
                continue
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
        reader = buffer.Reader(packet[1:])

        if msg_type == constants.ChannelMsg.OPEN:
            await self._handle_channel_open(reader)
        elif msg_type == constants.ChannelMsg.OPEN_CONFIRMATION:
            await self._handle_channel_open_confirmation(reader)
        elif msg_type == constants.ChannelMsg.OPEN_FAILURE:
            await self._handle_channel_open_failure(reader)
        elif msg_type == constants.ChannelMsg.DATA:
            await self._handle_channel_data(reader)
        elif msg_type == constants.ChannelMsg.WINDOW_ADJUST:
            await self._handle_window_adjust(reader)
        elif msg_type == constants.ChannelMsg.EOF:
            await self._handle_eof(reader)
        elif msg_type == constants.ChannelMsg.CLOSE:
            await self._handle_close(reader)

    async def _handle_channel_open(self, reader: buffer.Reader) -> None:
        """Handle SSH_MSG_CHANNEL_OPEN."""
        channel_type = reader.read_string()
        sender_channel = reader.read_uint32()
        initial_window = reader.read_uint32()
        _ = reader.read_uint32()  # max_packet

        local_id = self._next_id
        self._next_id += 1

        channel = Channel(local_id, sender_channel, channel_type.decode(), self, initial_window)
        self._channels[local_id] = channel

        await self._send_channel_open_confirmation(local_id, sender_channel, INITIAL_WINDOW, MAX_PACKET)
        await self._pending_open.put(channel)

    async def _handle_channel_open_confirmation(self, reader: buffer.Reader) -> None:
        """Handle SSH_MSG_CHANNEL_OPEN_CONFIRMATION."""
        recipient_channel = reader.read_uint32()
        sender_channel = reader.read_uint32()
        initial_window = reader.read_uint32()
        _ = reader.read_uint32()  # max_packet

        if recipient_channel not in self._open_results:
            return

        channel_type, future = self._open_results.pop(recipient_channel)  # type: ignore[misc]
        channel = Channel(recipient_channel, sender_channel, channel_type, self, initial_window)
        self._channels[recipient_channel] = channel
        future.set_result(channel)

    async def _handle_channel_open_failure(self, reader: buffer.Reader) -> None:
        """Handle SSH_MSG_CHANNEL_OPEN_FAILURE."""
        recipient_channel = reader.read_uint32()
        _ = reader.read_uint32()  # reason
        description = reader.read_string()

        if recipient_channel not in self._open_results:
            return

        _, future = self._open_results.pop(recipient_channel)  # type: ignore[misc]
        future.set_exception(exceptions.Error(f"Channel open failed: {description.decode()}"))

    async def _handle_channel_data(self, reader: buffer.Reader) -> None:
        """Handle SSH_MSG_CHANNEL_DATA."""
        recipient_channel = reader.read_uint32()
        data = reader.read_string()

        if recipient_channel not in self._channels:
            return

        channel = self._channels[recipient_channel]
        await channel._recv_data(data)  # type: ignore[reportPrivateUsage]
        # Send window adjust to replenish
        await self._send_window_adjust(recipient_channel, len(data))  # type: ignore[reportPrivateUsage]

    async def _handle_window_adjust(self, reader: buffer.Reader) -> None:
        """Handle SSH_MSG_CHANNEL_WINDOW_ADJUST."""
        recipient_channel = reader.read_uint32()
        bytes_to_add = reader.read_uint32()

        if recipient_channel not in self._channels:
            return

        channel = self._channels[recipient_channel]
        channel._recv_window_adjust(bytes_to_add)  # type: ignore[reportPrivateUsage]

    async def _handle_eof(self, reader: buffer.Reader) -> None:
        """Handle SSH_MSG_CHANNEL_EOF."""
        recipient_channel = reader.read_uint32()

        if recipient_channel not in self._channels:
            return

        channel = self._channels[recipient_channel]
        await channel._recv_eof()  # type: ignore[reportPrivateUsage]

    async def _handle_close(self, reader: buffer.Reader) -> None:
        """Handle SSH_MSG_CHANNEL_CLOSE."""
        recipient_channel = reader.read_uint32()

        if recipient_channel in self._channels:
            del self._channels[recipient_channel]

    async def _send_channel_open_confirmation(
        self, local_id: int, remote_id: int, initial_window: int, max_packet: int
    ) -> None:
        """Send SSH_MSG_CHANNEL_OPEN_CONFIRMATION."""
        w = buffer.Writer()
        w.write_byte(constants.ChannelMsg.OPEN_CONFIRMATION)
        w.write_uint32(remote_id)
        w.write_uint32(local_id)
        w.write_uint32(initial_window)
        w.write_uint32(max_packet)
        await self._write_packet(w.to_bytes())

    async def _send_channel_data(self, recipient_channel: int, data: bytes) -> None:
        """Send SSH_MSG_CHANNEL_DATA."""
        w = buffer.Writer()
        w.write_byte(constants.ChannelMsg.DATA)
        w.write_uint32(recipient_channel)
        w.write_string(data)
        await self._write_packet(w.to_bytes())

    async def _send_window_adjust(self, recipient_channel: int, bytes_to_add: int) -> None:
        """Send SSH_MSG_CHANNEL_WINDOW_ADJUST."""
        w = buffer.Writer()
        w.write_byte(constants.ChannelMsg.WINDOW_ADJUST)
        w.write_uint32(recipient_channel)
        w.write_uint32(bytes_to_add)
        await self._write_packet(w.to_bytes())

    async def _send_channel_eof(self, recipient_channel: int) -> None:
        """Send SSH_MSG_CHANNEL_EOF."""
        w = buffer.Writer()
        w.write_byte(constants.ChannelMsg.EOF)
        w.write_uint32(recipient_channel)
        await self._write_packet(w.to_bytes())

    async def _send_channel_close(self, recipient_channel: int) -> None:
        """Send SSH_MSG_CHANNEL_CLOSE."""
        w = buffer.Writer()
        w.write_byte(constants.ChannelMsg.CLOSE)
        w.write_uint32(recipient_channel)
        await self._write_packet(w.to_bytes())

    async def _send_channel_open(self, local_id: int, channel_type: str, initial_window: int, max_packet: int) -> None:
        """Send SSH_MSG_CHANNEL_OPEN."""
        w = buffer.Writer()
        w.write_byte(constants.ChannelMsg.OPEN)
        w.write_string(channel_type.encode())
        w.write_uint32(local_id)
        w.write_uint32(initial_window)
        w.write_uint32(max_packet)
        await self._write_packet(w.to_bytes())


class Server:
    """SSH channel server — accepts incoming channels."""

    def __init__(self, sock: tcp.TcpSocket) -> None:
        self._mux = _Mux(sock)

    async def accept(self) -> Channel:
        """Accept next incoming channel."""
        await self._mux._start()  # type: ignore[reportPrivateUsage]
        return await self._mux._pending_open.get()  # type: ignore[reportPrivateUsage]

    async def close(self) -> None:
        """Close server."""
        await self._mux._stop()  # type: ignore[reportPrivateUsage]
        self._mux._sock.close()  # type: ignore[reportPrivateUsage]


class Client:
    """SSH channel client — opens channels."""

    def __init__(self, sock: tcp.TcpSocket) -> None:
        self._mux = _Mux(sock)

    async def open_channel(self, channel_type: str) -> Channel:
        """Open a channel of given type."""
        await self._mux._start()  # type: ignore[reportPrivateUsage]

        local_id = self._mux._next_id  # type: ignore[reportPrivateUsage]
        self._mux._next_id += 1  # type: ignore[reportPrivateUsage]

        future: asyncio.Future[Channel] = asyncio.Future()
        self._mux._open_results[local_id] = (channel_type, future)  # type: ignore[reportPrivateUsage]

        await self._mux._send_channel_open(local_id, channel_type, INITIAL_WINDOW, MAX_PACKET)  # type: ignore[reportPrivateUsage]
        return await future

    async def close(self) -> None:
        """Close client."""
        await self._mux._stop()  # type: ignore[reportPrivateUsage]
        self._mux._sock.close()  # type: ignore[reportPrivateUsage]
