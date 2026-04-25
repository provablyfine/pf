from __future__ import annotations

import socket
import asyncio

class TcpSocket:
    """Async wrapper for socket."""

    def __init__(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        self._sock = sock

    async def accept(self) -> tuple[TcpSocket, object]:
        sock, addr = await asyncio.get_running_loop().sock_accept(self._sock)
        return TcpSocket(sock), addr

    async def send(self, data: bytes) -> None:
        await asyncio.get_running_loop().sock_sendall(self._sock, data)

    async def recv(self) -> bytes:
        try:
            data = await asyncio.get_running_loop().sock_recv(self._sock, 4096)
            return data
        except TimeoutError:
            return b""

    async def shutdown(self, flag: int) -> None:
        self._sock.shutdown(flag)

    def close(self) -> None:
        self._sock.close()
