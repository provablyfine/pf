from __future__ import annotations

import logging
import enum

from .. import ssh

logger = logging.getLogger(__name__)


class SearchState(enum.Enum):
    R = 1
    N = 2


class LineReader:
    def __init__(self, sock: ssh.tcp.TcpSocket):
        self._sock = sock
        self._buffer: bytes = b""

    async def read(self) -> bytes:
        state = SearchState.R
        current = 0
        while True:
            if len(self._buffer) < current:
                data = await self._sock.recv(4096)
                self._buffer += data
            byte = self._buffer[current:current+1]
            match state:
                case SearchState.R:
                    if byte == b"\r":
                        state = SearchState.N
                case SearchState.N:
                    if byte == b"\n":
                        line = self._buffer[:current]
                        self._buffer = self._buffer[current:]
                        return line

    def close(self) -> None:
        if len(self._buffer) != 0:
            raise Exception("Client sent data before getting a 200. It's illegal.")
