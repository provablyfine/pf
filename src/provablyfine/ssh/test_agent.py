import os
import sys

import pytest

from .. import jwk
from . import agent


class _FakeAddTransport:
    def __init__(self, responses: list[bytes]) -> None:
        self.sent: list[bytes] = []
        self._buffer = b"".join(responses)

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int) -> bytes:
        chunk, self._buffer = self._buffer[:n], self._buffer[n:]
        return chunk

    def close(self) -> None:
        pass


def _framed(message_type: int) -> bytes:
    return (1).to_bytes(4, "big") + bytes([message_type])


def test_pipe_transport_send_recv():
    # os.pipe() gives a portable byte-mode pipe pair to exercise the same
    # os.read/os.write path _PipeTransport uses against the real Windows
    # named pipe, without needing Windows or a running ssh-agent.
    read_fd, write_fd = os.pipe()
    reader = agent._PipeTransport(read_fd)
    writer = agent._PipeTransport(write_fd)
    writer.send(b"hello")
    assert reader.recv(5) == b"hello"
    os.close(read_fd)
    os.close(write_fd)


def test_pipe_transport_recv_short_read():
    read_fd, write_fd = os.pipe()
    reader = agent._PipeTransport(read_fd)
    writer = agent._PipeTransport(write_fd)
    writer.send(b"abc")
    # Asking for more than is currently available returns a short read,
    # exactly like socket.recv(n); the caller (_recv_bytes) loops for the rest.
    assert reader.recv(10) == b"abc"
    os.close(read_fd)
    os.close(write_fd)


def test_pipe_transport_recv_eof():
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    reader = agent._PipeTransport(read_fd)
    assert reader.recv(1) == b""
    os.close(read_fd)


def test_add_falls_back_to_unconstrained_on_windows(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(agent.sys, "platform", "win32")
    client = agent.Client.__new__(agent.Client)
    transport = _FakeAddTransport([_framed(agent.Client.SSH_AGENT_FAILURE), _framed(6)])
    client._transport = transport

    client._add(b"fake-key-bytes", "test-comment", lifetime=60)

    assert len(transport.sent) == 2
    assert transport.sent[0][4] == agent.Client.SSH_AGENTC_ADD_ID_CONSTRAINED
    assert transport.sent[1][4] == agent.Client.SSH_AGENTC_ADD_IDENTITY


def test_add_does_not_fall_back_when_confirmation_required(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(agent.sys, "platform", "win32")
    client = agent.Client.__new__(agent.Client)
    transport = _FakeAddTransport([_framed(agent.Client.SSH_AGENT_FAILURE)])
    client._transport = transport

    with pytest.raises(agent.exceptions.Error):
        client._add(b"fake-key-bytes", "test-comment", require_confirmation=True)

    assert len(transport.sent) == 1


def test_add_does_not_fall_back_on_posix(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(agent.sys, "platform", "linux")
    client = agent.Client.__new__(agent.Client)
    transport = _FakeAddTransport([_framed(agent.Client.SSH_AGENT_FAILURE)])
    client._transport = transport

    with pytest.raises(agent.exceptions.Error):
        client._add(b"fake-key-bytes", "test-comment", lifetime=60)

    assert len(transport.sent) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows named-pipe SSH agent transport")
def test_windows_agent_transport_against_real_service():
    try:
        client = agent.Client()
    except agent.exceptions.Error as e:
        pytest.skip(str(e))
    list(client.list_identities())


@pytest.mark.skipif(sys.platform != "win32", reason="Windows named-pipe SSH agent transport")
def test_windows_agent_add_with_lifetime_against_real_service():
    try:
        client = agent.Client()
    except agent.exceptions.Error as e:
        pytest.skip(str(e))
    key = jwk.Private.generate_ed25519()
    client.add(key, comment="pf-test-lifetime-fallback", lifetime=60)
    fingerprints = [identity.public_key.ssh_fingerprint() for identity in client.list_identities()]
    assert key.public().ssh_fingerprint() in fingerprints
