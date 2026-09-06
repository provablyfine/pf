"""Shared ssh-agent-wire protocol: framing (a 4-byte big-endian length
prefix, a 1-byte message type, then the payload) and message-type constants

This protocol is used by both `agent.Client` (the connecting side, talking to a real
ssh-agent or the oracle) and `oracle`'s accepting side.
"""

from __future__ import annotations

import contextlib
import dataclasses
import types
import typing

from . import buffer, exceptions

# https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENTC_ADD_IDENTITY = 17
SSH_AGENTC_REMOVE_IDENTITY = 18
SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
SSH_AGENTC_ADD_ID_CONSTRAINED = 25
SSH_AGENT_CONSTRAIN_LIFETIME = 1
SSH_AGENT_CONSTRAIN_CONFIRM = 2
SSH_AGENT_FAILURE = 5


@dataclasses.dataclass
class Message:
    type: int
    contents: bytes


class Transport(typing.Protocol):
    """The bytes-in/bytes-out surface `WireSocket` needs.

    `socket.socket` satisfies this as-is. So do the two thin adapters the
    Windows oracle needs -- one over the file object you get from opening a
    named pipe (`agent.py`, the connecting side), one over a raw connected
    pipe HANDLE (`oracle._win32.server`, the accepting side). Stated as a
    Protocol rather than hardcoding `socket.socket` purely so those two don't
    have to restate the framing below; the transport differs per platform, the
    bytes do not.

    `recv` returning `b""` means the peer is gone. An adapter over an API that
    signals that some other way -- a Windows pipe read fails with
    ERROR_BROKEN_PIPE rather than returning zero bytes -- must translate.
    """

    def recv(self, size: int, /) -> bytes: ...

    def send(self, data: bytes, /) -> int: ...

    def close(self) -> None: ...


class WireSocket:
    def __init__(self, sock: Transport) -> None:
        self._sock = sock

    def close(self) -> None:
        self._sock.close()

    def __del__(self) -> None:
        # try super hard to always close the underlying resource
        with contextlib.suppress(Exception):
            self.close()

    def __enter__(self) -> typing.Self:
        # It's important to use an explicit context manager to control
        # the lifetime of these objects because on Windows the
        # endpoint is a named pipe that serves one client at a time, so holding
        # it open past here can lock out the next opener
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
