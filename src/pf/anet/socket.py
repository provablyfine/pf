from __future__ import annotations

import asyncio
import enum
import functools
import socket as _socket
import typing
import logging

from . import base

logger = logging.getLogger(__name__)


class Family(enum.IntEnum):
    INET = _socket.AF_INET
    INET6 = _socket.AF_INET6
    UNIX = _socket.AF_UNIX


class Type(enum.IntEnum):
    STREAM = _socket.SOCK_STREAM


class Socket(base.Socket):
    def __init__(self, sock: _socket.socket):
        sock.setblocking(False)
        self._sock = sock

    @functools.cached_property
    def _loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        assert loop is not None
        return loop

    def fileno(self) -> int:
        return self._sock.fileno()

    async def connect(self, address: typing.Any) -> None:
        await self._loop.sock_connect(self._sock, address)

    def getsockname(self) -> typing.Any:
        return self._sock.getsockname()

    async def listen(self, n: int) -> None:
        self._sock.listen(n)

    async def accept(self) -> tuple[Socket, typing.Any]:
        sock, addr = await self._loop.sock_accept(self._sock)
        return Socket(sock), addr

    async def bind(self, address: typing.Any) -> None:
        self._sock.bind(address)

    async def send(self, data: bytes) -> int:
        await self._loop.sock_sendall(self._sock, data)
        return len(data)

    async def recv(self, n: int) -> bytes:
        """Receive up to n bytes. Returns b'' on EOF or timeout."""
        data = await self._loop.sock_recv(self._sock, n)
        return data

    async def shutdown(self, flag: base.Shut) -> None:
        self._sock.shutdown(flag)

    def close(self) -> None:
        self._sock.close()


def socket(
    family: Family,
    type: Type,
    fileno: int | None = None,
) -> Socket:
    sock = _socket.socket(family, type, proto=0, fileno=fileno)
    return Socket(sock)


def socketpair(
    family: Family,
    type: Type,
) -> tuple[Socket, Socket]:
    a, b = _socket.socketpair(family, type, 0)
    return Socket(a), Socket(b)
