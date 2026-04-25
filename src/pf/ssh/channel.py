"""Public SSH channel API."""

from __future__ import annotations

from . import _mux, tcp

# Re-export constants for backward compatibility
MAX_PACKET = _mux.MAX_PACKET


class Channel:
    """Public SSH channel handle."""

    def __init__(self, impl: _mux.ChannelImpl) -> None:
        self._impl = impl

    @property
    def channel_type(self) -> str:
        """Channel type (e.g., 'session')."""
        return self._impl.channel_type

    async def read(self) -> bytes:
        """Read data from channel. Returns b'' on EOF."""
        return await self._impl.read()

    async def write(self, data: bytes) -> None:
        """Write data to channel, respecting send window."""
        await self._impl.write(data)

    async def close(self) -> None:
        """Close channel."""
        await self._impl.close()


class Server:
    """SSH channel server — accepts incoming channels."""

    def __init__(self, sock: tcp.TcpSocket) -> None:
        self._mux = _mux.Mux(sock)

    async def accept(self) -> Channel:
        """Accept next incoming channel."""
        return Channel(await self._mux.accept())

    async def close(self) -> None:
        """Close server."""
        await self._mux.stop()
        self._mux.close_socket()


class Client:
    """SSH channel client — opens channels."""

    def __init__(self, sock: tcp.TcpSocket) -> None:
        self._mux = _mux.Mux(sock)

    async def open_channel(self, channel_type: str) -> Channel:
        """Open a channel of given type."""
        return Channel(await self._mux.open_channel(channel_type))

    async def close(self) -> None:
        """Close client."""
        await self._mux.stop()
        self._mux.close_socket()
