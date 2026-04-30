import logging

from . import base

logger = logging.getLogger(__name__)


class IncompleteReadError(EOFError):
    def __init__(self):
        super().__init__("Connection closed before delimiter was found")


class Reader:
    def __init__(self, sock: base.Socket):
        self._sock = sock
        self._buffer = bytearray()

    async def read_until(self, delimiter: bytes) -> bytes:
        while True:
            idx = self._buffer.find(delimiter)
            if idx != -1:
                # The delimiter is already in our buffer
                end = idx + len(delimiter)
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result

            # Not in buffer
            logger.debug("start read")
            chunk = await self._sock.recv(4096)
            logger.debug(f"end read chunk={chunk}")
            
            if chunk == b"":
                raise IncompleteReadError()

            self._buffer.extend(chunk)

    async def read(self, n: int) -> bytes:
        while True:
            logger.debug("start read")
            chunk = await self._sock.recv(n-len(self._buffer))
            logger.debug(f"end read chunk={chunk}")
            self._buffer.extend(chunk)
            if len(self._buffer) >= n:
                result = bytes(self._buffer[:n])
                del self._buffer[:n]
                return result
            if chunk == b"":
                raise IncompleteReadError()
