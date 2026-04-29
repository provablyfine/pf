from __future__ import annotations

from .. import anet
from . import _mux


class Channel:
    """Public channel handle."""

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

    async def close_write(self) -> None:
        """Half-close write side. Peer receives EOF, but can still send."""
        await self._impl.close_write()

    async def close(self) -> None:
        """Fully close channel."""
        await self._impl.close()


class Server:
    """SSH channel server — accepts incoming channels."""

    def __init__(self, sock: anet.base.Socket) -> None:
        self._mux = _mux.Mux(sock)

    async def accept(self) -> Channel:
        """Accept next incoming channel."""
        return Channel(await self._mux.accept())

    async def close(self) -> None:
        """Close server."""
        await self._mux.stop()
        await self._mux.close_socket()


class Client:
    """SSH channel client — opens channels."""

    def __init__(self, sock: anet.base.Socket) -> None:
        self._mux = _mux.Mux(sock)

    async def open_channel(self) -> Channel:
        """Open a channel."""
        return Channel(await self._mux.open_channel("session"))

    async def close(self) -> None:
        """Close client."""
        await self._mux.stop()
        await self._mux.close_socket()

    async def wait_closed(self) -> None:
        """Wait until remote closes the connection."""
        await self._mux.wait_closed()
