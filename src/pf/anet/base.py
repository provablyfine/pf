import abc
import enum
import socket as _socket


class Shut(enum.IntEnum):
    RD = _socket.SHUT_RD
    WR = _socket.SHUT_WR
    RDWR = _socket.SHUT_RDWR


class Socket(abc.ABC):
    @abc.abstractmethod
    async def send(self, data: bytes) -> int:
        pass

    @abc.abstractmethod
    async def recv(self, n: int) -> bytes:
        pass

    @abc.abstractmethod
    async def shutdown(self, flag: Shut) -> None:
        pass

    @abc.abstractmethod
    async def close(self) -> None:
        pass
