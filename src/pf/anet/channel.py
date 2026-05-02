from __future__ import annotations

from . import _mux


class Channel:
    """Public channel handle."""

    def __init__(self, local_id: int, mux: _mux.Mux) -> None:
        self._local_id = local_id
        self._mux = mux

    async def read(self) -> bytes:
        """Read data from channel. Returns b'' on EOF."""
        return await self._mux.channel_read(self._local_id)

    async def write(self, data: bytes) -> None:
        """Write data to channel, respecting send window."""
        await self._mux.channel_write(self._local_id, data)

    async def close_write(self) -> None:
        """Half-close write side. Peer receives EOF, but can still send."""
        await self._mux.channel_close_write(self._local_id)

    async def close(self) -> None:
        """Fully close channel."""
        await self._mux.channel_close(self._local_id)


class Server:
    """SSH channel server — accepts incoming channels."""

    def __init__(self, socket_name: str) -> None:
        self._mux = _mux.Mux.create(socket_name)

    async def accept(self) -> Channel:
        """Accept next incoming channel."""
        local_id = await self._mux.channel_accept()
        return Channel(local_id, self._mux)

    async def close(self) -> None:
        """Close server."""
        await self._mux.stop()
        await self._mux.close_socket()


class Client:
    """SSH channel client — opens channels."""

    def __init__(self, socket_name: str) -> None:
        self._mux = _mux.Mux.create(socket_name)

    async def open_channel(self) -> Channel:
        """Open a channel."""
        local_id = await self._mux.channel_open()
        return Channel(local_id, self._mux)

    async def close(self) -> None:
        """Close client."""
        await self._mux.stop()
        await self._mux.close_socket()

    async def wait_closed(self) -> None:
        """Wait until remote closes the connection."""
        await self._mux.wait_closed()
