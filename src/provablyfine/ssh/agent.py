from __future__ import annotations

import collections.abc
import dataclasses
import getpass
import logging
import os
import socket
import sys
import typing

from .. import jwk
from . import buffer, cert, exceptions, serde

logger = logging.getLogger(__name__)

# Windows' built-in OpenSSH Authentication Agent service listens on this
# well-known named pipe. It ships disabled by default, even on Windows 11.
WELL_KNOWN_PIPE = r"\\.\pipe\openssh-ssh-agent"

_ENABLE_AGENT_HINT = (
    "No SSH agent found. Windows' OpenSSH Authentication Agent service is disabled by default.\n"
    "Enable it in an elevated PowerShell with:\n"
    "  Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent"
)


class _Transport(typing.Protocol):
    def send(self, data: bytes) -> None: ...
    def recv(self, n: int) -> bytes: ...
    def close(self) -> None: ...


class _SocketTransport:
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def send(self, data: bytes) -> None:
        written = self._sock.send(data)
        assert written == len(data)

    def recv(self, n: int) -> bytes:
        return self._sock.recv(n)

    def close(self) -> None:
        self._sock.close()


class _PipeTransport:
    # Win32-OpenSSH's ssh-agent named pipe is a byte-mode pipe (confirmed by
    # testing: multiprocessing.connection.Client, which forces
    # PIPE_READMODE_MESSAGE via SetNamedPipeHandleState, fails against it with
    # WinError 87/ERROR_INVALID_PARAMETER — that call only succeeds against a
    # pipe created as PIPE_TYPE_MESSAGE). A byte-mode pipe is just a regular
    # Windows file handle, so plain os.open/os.read/os.write (opened with
    # O_BINARY to avoid CRLF translation on the binary protocol) talk to it
    # directly, with the exact same "up to n bytes, b'' on EOF" semantics as
    # socket.recv — no extra dependency, no message-framing assumptions needed.
    def __init__(self, fd: int) -> None:
        self._fd = fd

    def send(self, data: bytes) -> None:
        written = os.write(self._fd, data)
        assert written == len(data)

    def recv(self, n: int) -> bytes:
        return os.read(self._fd, n)

    def close(self) -> None:
        os.close(self._fd)


def _connect_pipe(path: str) -> _Transport:
    fd = os.open(path, os.O_RDWR | os.O_BINARY)
    return _PipeTransport(fd)


def _connect_windows() -> _Transport:
    auth_sock = os.environ.get("SSH_AUTH_SOCK")
    if auth_sock:
        try:
            return _connect_pipe(auth_sock)
        except OSError:
            pass
        if hasattr(socket, "AF_UNIX"):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(auth_sock)
                return _SocketTransport(sock)
            except OSError:
                pass
        raise exceptions.Error(f"Could not connect to SSH agent at SSH_AUTH_SOCK={auth_sock!r}")
    try:
        return _connect_pipe(WELL_KNOWN_PIPE)
    except OSError as e:
        raise exceptions.Error(_ENABLE_AGENT_HINT) from e


@dataclasses.dataclass
class Identity:
    public_key: jwk.Public
    comment: str
    raw: bytes


@dataclasses.dataclass
class Message:
    type: int
    contents: bytes


class Client:
    # https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
    SSH_AGENTC_REQUEST_IDENTITIES = 11
    SSH_AGENT_IDENTITIES_ANSWER = 12
    SSH_AGENTC_SIGN_REQUEST = 13
    SSH_AGENTC_ADD_IDENTITY = 17
    SSH_AGENTC_REMOVE_IDENTITY = 18
    SSH_AGENTC_REMOVE_ALL_IDENTITIES = 19
    SSH_AGENTC_ADD_ID_CONSTRAINED = 25
    SSH_AGENT_CONSTRAIN_LIFETIME = 1
    SSH_AGENT_CONSTRAIN_CONFIRM = 2
    SSH_AGENT_FAILURE = 5

    def __init__(self):
        if sys.platform == "win32":
            self._transport: _Transport = _connect_windows()
            return
        path = os.environ["SSH_AUTH_SOCK"]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path.encode("ascii"))
        self._transport = _SocketTransport(sock)

    def close(self) -> None:
        self._transport.close()

    def __del__(self) -> None:
        # Nothing closes Client explicitly at most call sites, and on Windows a
        # connection left open past its last use can contend with a *different*
        # process (e.g. an ssh.exe child spawned by ssh_cli.py) trying to open
        # the same named pipe. Release it as soon as the object is collected
        # instead of only at process exit.
        transport = getattr(self, "_transport", None)
        if transport is not None:
            try:
                transport.close()
            except OSError:
                pass

    def _send_request(self, type: int, data: bytes):
        request = buffer.Writer()
        request.write_uint32(len(data) + 1)
        request.write_byte(type)
        request.write_bytes(data)
        self._transport.send(request.to_bytes())

    def _recv_bytes(self, n: int) -> bytes:
        remaining = n
        data: list[bytes] = []
        while remaining > 0:
            partial = self._transport.recv(remaining)
            if len(partial) == 0:
                raise exceptions.Error("Unable to read SSH Agent response")
            remaining -= len(partial)
            data.append(partial)
        return b"".join(data)

    def _recv_message(self):
        length = self._recv_bytes(4)
        length = int.from_bytes(length, byteorder="big")
        payload = self._recv_bytes(length)
        return Message(type=payload[0], contents=payload[1:])

    def list_identities(self) -> collections.abc.Generator[Identity]:
        self._send_request(Client.SSH_AGENTC_REQUEST_IDENTITIES, b"")
        rx = self._recv_message()
        assert rx.type == Client.SSH_AGENT_IDENTITIES_ANSWER
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
        self._send_request(Client.SSH_AGENTC_SIGN_REQUEST, request.to_bytes())
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
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
        unconstrained = buffer.Writer()
        unconstrained.write_bytes(key)
        unconstrained.write_string(comment.encode("utf-8"))

        if lifetime is None and not require_confirmation:
            self._send_request(Client.SSH_AGENTC_ADD_IDENTITY, unconstrained.to_bytes())
            message = self._recv_message()
        else:
            request = buffer.Writer()
            request.write_bytes(key)
            request.write_string(comment.encode("utf-8"))
            if lifetime is not None:
                request.write_byte(Client.SSH_AGENT_CONSTRAIN_LIFETIME)
                request.write_uint32(lifetime)
            if require_confirmation:
                request.write_byte(Client.SSH_AGENT_CONSTRAIN_CONFIRM)
            self._send_request(Client.SSH_AGENTC_ADD_ID_CONSTRAINED, request.to_bytes())
            message = self._recv_message()
            # Windows' OpenSSH agent doesn't support SSH_AGENTC_ADD_ID_CONSTRAINED at
            # all. Fall back to an unconstrained add for the lifetime-only case (the
            # only constraint kind actually used today) rather than blocking every
            # pf login/pf ssh on Windows — but never silently drop a confirmation
            # requirement, since that's a real security-relevant control.
            if message.type == Client.SSH_AGENT_FAILURE and sys.platform == "win32" and not require_confirmation:
                logger.warning(
                    "Windows OpenSSH agent rejected a lifetime-constrained key add; retrying "
                    "without the lifetime constraint. The key will persist in the agent until "
                    "removed explicitly."
                )
                self._send_request(Client.SSH_AGENTC_ADD_IDENTITY, unconstrained.to_bytes())
                message = self._recv_message()

        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to add key to agent: {message.contents}")

    def remove_all(self):
        self._send_request(Client.SSH_AGENTC_REMOVE_ALL_IDENTITIES, b"")
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove keys from agent: {message.contents}")

    def remove(self, identity: Identity):
        request = buffer.Writer()
        request.write_string(identity.raw)
        self._send_request(Client.SSH_AGENTC_REMOVE_IDENTITY, request.to_bytes())
        message = self._recv_message()
        if message.type == Client.SSH_AGENT_FAILURE:
            raise exceptions.Error(f"Unable to remove key from agent: {message.contents}")
