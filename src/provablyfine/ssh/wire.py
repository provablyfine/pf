"""Shared ssh-agent-wire framing: a 4-byte big-endian length prefix, a 1-byte
message type, then the payload -- used by both `agent.Client` (the connecting
side, talking to a real ssh-agent or the oracle) and `oracle.protocol.Connection`
(the accepting side, talking to a client).
"""

from __future__ import annotations

import dataclasses
import socket
import types
import typing

from . import buffer, exceptions


@dataclasses.dataclass
class Message:
    type: int
    contents: bytes


class WireSocket:
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None:
        self.close()

    def _recv_bytes(self, n: int) -> bytes:
        remaining = n
        data: list[bytes] = []
        while remaining > 0:
            partial = self._sock.recv(remaining)
            if len(partial) == 0:
                raise exceptions.Error("Peer closed the connection")
            remaining -= len(partial)
            data.append(partial)
        return b"".join(data)

    def recv_message(self) -> Message:
        length = self._recv_bytes(4)
        length_int = int.from_bytes(length, byteorder="big")
        if length_int == 0:
            raise exceptions.Error("Received an empty message")
        payload = self._recv_bytes(length_int)
        return Message(type=payload[0], contents=payload[1:])

    def send_message(self, type: int, contents: bytes) -> None:
        writer = buffer.Writer()
        writer.write_uint32(len(contents) + 1)
        writer.write_byte(type)
        writer.write_bytes(contents)
        data = writer.to_bytes()
        sent_total = 0
        while sent_total < len(data):
            sent = self._sock.send(data[sent_total:])
            if sent == 0:
                raise exceptions.Error("Unable to write message")
            sent_total += sent
