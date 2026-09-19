from __future__ import annotations

import collections.abc
import dataclasses
import getpass
import os
import socket
import sys
import time
import typing

from .. import jwk
from . import buffer, cert, exceptions, serde, wire


@dataclasses.dataclass
class Identity:
    public_key: jwk.Public
    comment: str
    raw: bytes


# How long a client waits for a pipe whose instances are all busy.
_PIPE_BUSY_TIMEOUT_SECONDS = 5.0


def _open_pipe(name: str) -> typing.BinaryIO:
    """Open the named pipe `name`, waiting for its turn if it is busy.

    A pipe instance serves one client at a time. pf's oracle has a single
    instance, so a client that arrives while another is being served, or while
    the server is re-arming after the previous one, is told the pipe is busy.
    The system ssh-agent behaves the same way.

    The C runtime reports that as a bare `EINVAL`, so `open()` cannot tell it
    apart from other failures. `WaitNamedPipe` can: it only succeeds when the
    pipe exists and an instance becomes free. A pipe that does not exist, or
    that we may not open, fails at once.
    """
    import provablyfine.ssh.oracle._win32._win32api

    deadline = time.monotonic() + _PIPE_BUSY_TIMEOUT_SECONDS
    while True:
        try:
            return open(name, "r+b", buffering=0)
        except (FileNotFoundError, PermissionError):
            raise
        except OSError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not provablyfine.ssh.oracle._win32._win32api.wait_named_pipe(
                name, int(remaining * 1000)
            ):
                raise
            time.sleep(0.005)


class _PipeTransport:
    """`wire.Transport` over a Windows named pipe.

    On Windows an agent endpoint is a named pipe, not a UNIX socket -- both
    the system ssh-agent (`\\\\.\\pipe\\openssh-ssh-agent`) and pf's own
    oracle. A pipe opened this way reads and writes like an ordinary
    binary file, so no ctypes is needed here.
    """

    def __init__(self, name: str) -> None:
        # `open()` raises `FileNotFoundError` when nothing is listening:
        # `client/http_client.py` takes advantage of that to distinguish "the
        # oracle is gone, log in again" from every other failure by catching
        # `OSError`
        self._stream = _open_pipe(name)

    def recv(self, size: int) -> bytes:
        return self._stream.read(size) or b""

    def send(self, data: bytes) -> int:
        return self._stream.write(data) or 0

    def close(self) -> None:
        self._stream.close()


# Where Windows' OpenSSH agent listens. Unlike POSIX, there is no environment
# variable pointing at it by convention: the pipe name is fixed and clients
# are expected to know it.
_WINDOWS_AGENT_PIPE = r"\\.\pipe\openssh-ssh-agent"


def _connect(path: str) -> wire.Transport:
    if sys.platform == "win32":
        return _PipeTransport(path)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path.encode("ascii"))
        return sock


class Client(wire.WireSocket):
    def __init__(self, path: str | None = None):
        if path is None:
            if sys.platform == "win32":
                path = _WINDOWS_AGENT_PIPE
            else:
                path = os.environ.get("SSH_AUTH_SOCK")
                if path is None:
                    raise OSError("SSH_AUTH_SOCK is not set")
        super().__init__(_connect(path))

    def list_identities(self) -> collections.abc.Generator[Identity]:
        self.send_message(wire.SSH_AGENTC_REQUEST_IDENTITIES, b"")
        rx = self.recv_message()
        assert rx.type == wire.SSH_AGENT_IDENTITIES_ANSWER
        assert len(rx.contents) >= 4
        response = buffer.Reader(rx.contents)
        nkeys = response.read_uint32()
        for _ in range(nkeys):
            raw_key = response.read_string()
            key = serde.deserialize_public(raw_key)
            comment = response.read_string()
            yield Identity(public_key=key, comment=comment.decode("utf-8"), raw=raw_key)

    def sign(self, identity: Identity, data: bytes, flags: int) -> bytes:
        request = buffer.Writer()
        request.write_string(identity.raw)
        request.write_string(data)
        request.write_uint32(flags)
        self.send_message(wire.SSH_AGENTC_SIGN_REQUEST, request.to_bytes())
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to obtain signature from agent: {message.contents}")
        response = buffer.Reader(message.contents)
        _length = response.read_uint32()
        _key_type = response.read_string()
        signature = response.read_string()
        return signature

    def add(
        self,
        private_key: jwk.Private,
        cert: cert.Cert | None = None,
        comment: str | None = None,
        lifetime: int | None = None,
        require_confirmation: bool = False,
    ):
        if cert is None:
            key = serde.serialize_private(private_key)
        else:
            key = serde.serialize_private_certificate(private_key, cert)
        if comment is None:
            comment = f"{getpass.getuser()}@{socket.gethostname()}"
        self._add(key, comment, lifetime, require_confirmation)

    def _add(self, key: bytes, comment: str, lifetime: int | None = None, require_confirmation: bool = False):
        request = buffer.Writer()
        request.write_bytes(key)
        request.write_string(comment.encode("utf-8"))
        request_id = wire.SSH_AGENTC_ADD_IDENTITY
        if lifetime is not None:
            request_id = wire.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(wire.SSH_AGENT_CONSTRAIN_LIFETIME)
            request.write_uint32(lifetime)
        if require_confirmation:
            request_id = wire.SSH_AGENTC_ADD_ID_CONSTRAINED
            request.write_byte(wire.SSH_AGENT_CONSTRAIN_CONFIRM)
        self.send_message(request_id, request.to_bytes())
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to add key to agent: {message.contents}")

    def remove_all(self):
        self.send_message(wire.SSH_AGENTC_REMOVE_ALL_IDENTITIES, b"")
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove keys from agent: {message.contents}")

    def remove(self, identity: Identity):
        request = buffer.Writer()
        request.write_string(identity.raw)
        self.send_message(wire.SSH_AGENTC_REMOVE_IDENTITY, request.to_bytes())
        message = self.recv_message()
        if message.type == wire.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove key from agent: {message.contents}")
