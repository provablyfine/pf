from __future__ import annotations

import asyncio
import socket
import typing


class TcpSocket:
    """Non-blocking TCP socket for async I/O."""

    def __init__(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        self._sock = sock

    async def accept(self) -> tuple[TcpSocket, typing.Any]:
        """Accept incoming connection. Returns (socket, address)."""
        sock, addr = await asyncio.get_running_loop().sock_accept(self._sock)
        return TcpSocket(sock), addr

    async def send(self, data: bytes) -> None:
        """Send all data."""
        await asyncio.get_running_loop().sock_sendall(self._sock, data)

    async def recv(self, n: int) -> bytes:
        """Receive up to n bytes. Returns b'' on EOF or timeout."""
        try:
            data = await asyncio.get_running_loop().sock_recv(self._sock, n)
            return data
        except TimeoutError:
            return b""

    async def shutdown(self, flag: int) -> None:
        """Shutdown socket (SHUT_RD, SHUT_WR, SHUT_RDWR)."""
        self._sock.shutdown(flag)

    def close(self) -> None:
        """Close socket."""
        self._sock.close()

    def listen(self, n: int) -> None:
        """Listen for incoming connections."""
        self._sock.listen(n)
