import abc
import enum
import socket as _socket
import typing


class Shut(enum.IntEnum):
    RD = _socket.SHUT_RD
    WR = _socket.SHUT_WR
    RDWR = _socket.SHUT_RDWR


class Socket(abc.ABC):
    @abc.abstractmethod
    def fileno(self) -> int:
        pass

    @abc.abstractmethod
    def detach(self) -> int:
        pass

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
    def close(self) -> None:
        pass

    @abc.abstractmethod
    def getsockname(self) -> typing.Any:
        pass

    @abc.abstractmethod
    async def bind(self, address: typing.Any) -> None:
        pass

    @abc.abstractmethod
    async def listen(self, n: int) -> None:
        pass

    @abc.abstractmethod
    async def accept(self) -> tuple["Socket", typing.Any]:
        pass
