"""The Windows end of the ssh-agent client."""

from __future__ import annotations

import msvcrt
import os
import time
import typing

from . import _w32 as w32
from . import exceptions, wire

# Where Windows' OpenSSH agent listens. Unlike POSIX, there is no environment
# variable pointing at it by convention: the pipe name is fixed and clients
# are expected to know it.
WINDOWS_AGENT_PIPE = r"\\.\pipe\openssh-ssh-agent"

# How long a client waits for a pipe whose instances are all busy.
_PIPE_BUSY_TIMEOUT_SECONDS = 5.0


def _open_pipe(name: str) -> typing.BinaryIO:
    """Open the named pipe `name` for duplex byte I/O, waiting for a free
    instance if they are all busy.

    A pipe instance serves one client at a time. pf's oracle has a single
    instance, so a client that arrives while another is being served, or while
    the server is re-arming after the previous one, is told the pipe is busy.
    """
    deadline = time.monotonic() + _PIPE_BUSY_TIMEOUT_SECONDS
    while True:
        try:
            return _open_once(name)
        except (FileNotFoundError, PermissionError):
            raise
        except OSError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not w32.pipe.wait_named_pipe(name, max(1, int(remaining * 1000))):
                raise
            time.sleep(0.005)


def _open_once(name: str) -> typing.BinaryIO:
    # The pipe HANDLE becomes a Python file object through the CRT, exactly as
    # `open()` would have made one; the transport only ever reads and writes it.
    handle = w32.pipe.open_client(name)
    return os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDWR), "r+b", buffering=0)


class PipeTransport:
    """`wire.Transport` over a Windows named pipe.

    `_open_pipe` raises `FileNotFoundError` when nothing is listening:
    `client/http_client.py` takes advantage of that to distinguish "the oracle
    is gone, log in again" from every other failure by catching `OSError`.
    """

    def __init__(self, name: str, *, check_owner: bool = False) -> None:
        self._stream = _open_pipe(name)
        if check_owner:
            try:
                _check_owner(self._stream, name)
            except Exception:
                self._stream.close()
                raise

    def recv(self, size: int) -> bytes:
        return self._stream.read(size) or b""

    def send(self, data: bytes) -> int:
        return self._stream.write(data) or 0

    def close(self) -> None:
        self._stream.close()


def connect(path: str | None, *, check_owner: bool = False) -> wire.Transport:
    return PipeTransport(path if path is not None else WINDOWS_AGENT_PIPE, check_owner=check_owner)


def _check_owner(stream: typing.BinaryIO, name: str) -> None:
    # The stream owns the handle, so this only borrows it for one call.
    handle = msvcrt.get_osfhandle(stream.fileno())
    try:
        server = w32.process.open_process(w32.pipe.named_pipe_server_pid(handle))
        if server is None:
            raise exceptions.Error("Server process exited before its owner could be read")
        try:
            peer_sid = w32.security.process_user_sid(server)
        finally:
            w32.process.close_handle(server)
        our_sid = w32.security.current_user_sid()
    except (exceptions.Error, OSError) as e:
        raise exceptions.OraclePeerCheckFailed(f"Unable to check who serves {name}: {e}") from e
    if peer_sid != our_sid:
        raise exceptions.OraclePeerCheckFailed(
            f"{name} is served by a process running as {peer_sid}, not by you ({our_sid})."
        )
