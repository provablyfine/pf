"""Tests for the frame-size limits in `wire`."""

from __future__ import annotations

import pytest

from . import exceptions, wire


class _MemoryTransport(wire.Transport):
    """A `Transport` serving bytes from a fixed buffer, recording the size
    requested by every `recv` call."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self.requested_sizes: list[int] = []

    def recv(self, size: int, /) -> bytes:
        self.requested_sizes.append(size)
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def send(self, data: bytes, /) -> int:
        raise NotImplementedError

    def close(self) -> None:
        pass


def test_recv_message_rejects_oversized_frame() -> None:
    # Only the 4-byte header is offered, so a reader that correctly rejects
    # the frame on the size check succeeds while one that tries to read the
    # advertised payload would fail on the closed connection.
    frame = (wire.MAX_MESSAGE_LENGTH + 1).to_bytes(4, byteorder="big")
    transport = _MemoryTransport(frame)
    with pytest.raises(exceptions.Error, match="larger than"):
        wire.WireSocket(transport).recv_message()
    assert transport.requested_sizes == [4]


def test_recv_message_reads_in_bounded_chunks() -> None:
    payload = bytes([wire.SSH_AGENT_SIGN_RESPONSE]) + b"x" * (2 * wire.RECV_CHUNK_SIZE + 17)
    transport = _MemoryTransport(len(payload).to_bytes(4, byteorder="big") + payload)
    message = wire.WireSocket(transport).recv_message()
    assert message.type == wire.SSH_AGENT_SIGN_RESPONSE
    assert message.contents == payload[1:]
    assert max(transport.requested_sizes) <= wire.RECV_CHUNK_SIZE
