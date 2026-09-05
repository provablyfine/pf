"""Wire framing for the oracle's ssh-agent-compatible protocol.

Reuses `ssh/buffer.py`'s Reader/Writer for payload serialization -- no new
serialization code, only the message-level framing (a 4-byte big-endian
length prefix, a 1-byte message type, then the payload), mirroring
`agent.Client`'s own `_send_request`/`_recv_message` but for the server side
of the connection.
"""

from __future__ import annotations

import dataclasses
import socket

from .. import buffer, exceptions

# https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14
SSH_AGENT_FAILURE = 5


@dataclasses.dataclass
class Message:
    type: int
    contents: bytes


class Connection:
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _recv_bytes(self, n: int) -> bytes:
        remaining = n
        data: list[bytes] = []
        while remaining > 0:
            partial = self._sock.recv(remaining)
            if len(partial) == 0:
                raise exceptions.Error("Peer closed the oracle connection")
            remaining -= len(partial)
            data.append(partial)
        return b"".join(data)

    def recv_message(self) -> Message:
        length = self._recv_bytes(4)
        length_int = int.from_bytes(length, byteorder="big")
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
                raise exceptions.Error("Unable to write oracle response")
            sent_total += sent
