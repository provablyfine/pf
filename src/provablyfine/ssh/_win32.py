"""The Windows end of the ssh-agent client."""

from __future__ import annotations

import ctypes
import msvcrt
import os
import time
import typing

from . import _win32_bindings as bindings
from . import wire

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
    The system ssh-agent behaves the same way. `WaitNamedPipeW` is what makes
    that waitable rather than fatal: it only succeeds when the pipe exists and
    an instance becomes free. A pipe that does not exist, or that we may not
    open, fails at once.
    """
    deadline = time.monotonic() + _PIPE_BUSY_TIMEOUT_SECONDS
    while True:
        try:
            return _open_once(name)
        except (FileNotFoundError, PermissionError):
            raise
        except OSError:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not bindings.k32.WaitNamedPipeW(name, max(1, int(remaining * 1000))):
                raise
            time.sleep(0.005)


def _open_once(name: str) -> typing.BinaryIO:
    handle = bindings.k32.CreateFileW(
        name,
        bindings.GENERIC_READ | bindings.GENERIC_WRITE,
        0,
        None,
        bindings.OPEN_EXISTING,
        bindings.SECURITY_SQOS_PRESENT | bindings.SECURITY_ANONYMOUS,
        None,
    )
    if handle == bindings.INVALID_HANDLE_VALUE or not handle:
        # `ctypes.WinError` maps the code to the right `OSError` subclass, so
        # "no such pipe" stays a `FileNotFoundError` and "the DACL says no"
        # stays a `PermissionError`, exactly as Python's `open()` reported them.
        raise ctypes.WinError(code=ctypes.get_last_error())
    return os.fdopen(msvcrt.open_osfhandle(handle, os.O_RDWR), "r+b", buffering=0)


class PipeTransport:
    """`wire.Transport` over a Windows named pipe.

    `_open_pipe` raises `FileNotFoundError` when nothing is listening:
    `client/http_client.py` takes advantage of that to distinguish "the oracle
    is gone, log in again" from every other failure by catching `OSError`.
    """

    def __init__(self, name: str) -> None:
        self._stream = _open_pipe(name)

    def recv(self, size: int) -> bytes:
        return self._stream.read(size) or b""

    def send(self, data: bytes) -> int:
        return self._stream.write(data) or 0

    def close(self) -> None:
        self._stream.close()


def connect(path: str | None) -> wire.Transport:
    return PipeTransport(path if path is not None else WINDOWS_AGENT_PIPE)
