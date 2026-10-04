"""Named pipes: creation, connection, byte I/O, and the kernel's record of the
peer on each end.

`create_named_pipe` bakes in the defaults every pf pipe wants -- an owner-only
DACL and `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a squatter turns into a loud
failure rather than a shared name.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes

from . import errors, raw, security


def create_named_pipe(name: str, *, inheritable: bool) -> int:
    """Create the listening pipe, refusing to become a *second* instance.

    `FILE_FLAG_FIRST_PIPE_INSTANCE` is what turns "someone already claimed this
    name" from a silent compromise into a loud failure: without it we would
    cheerfully add an instance alongside a squatter's, and clients would reach
    whichever happened to be pending.
    """
    handle = try_create_named_pipe(name, inheritable=inheritable)
    if handle is None:
        errors.raise_last_error(f"CreateNamedPipeW({name})")
    return handle


def try_create_named_pipe(name: str, *, inheritable: bool) -> int | None:
    """`create_named_pipe`, returning None instead of raising when the name is
    already taken.

    Separate from the raising version so the new-login retry loop can tell
    "wait, the predecessor still holds it" apart from a real failure, instead of
    retrying blindly on any error. `ERROR_ACCESS_DENIED` is what
    FIRST_PIPE_INSTANCE reports for a name that already exists.
    """
    owner = security.owner_only_security_attributes(inheritable=inheritable)
    handle = raw.k32.CreateNamedPipeW(
        name,
        raw.PIPE_ACCESS_DUPLEX | raw.FILE_FLAG_FIRST_PIPE_INSTANCE,
        raw.PIPE_TYPE_BYTE | raw.PIPE_READMODE_BYTE | raw.PIPE_WAIT | raw.PIPE_REJECT_REMOTE_CLIENTS,
        raw.PIPE_UNLIMITED_INSTANCES,
        65536,
        65536,
        0,
        ctypes.byref(owner.attributes),
    )
    if handle == raw.INVALID_HANDLE_VALUE or not handle:
        if ctypes.get_last_error() in (raw.ERROR_ACCESS_DENIED, raw.ERROR_PIPE_BUSY):
            return None
        errors.raise_last_error(f"CreateNamedPipeW({name})")
    return handle


def connect_named_pipe(handle: int) -> None:
    """Block until a client connects.

    `ERROR_PIPE_CONNECTED` is success, not failure: it means a client got in
    during the window between the pipe being created (or disconnected) and this
    call. That is routine.
    """
    if raw.k32.ConnectNamedPipe(handle, None):
        return
    if ctypes.get_last_error() == raw.ERROR_PIPE_CONNECTED:
        return
    errors.raise_last_error("ConnectNamedPipe")


def disconnect_named_pipe(handle: int) -> None:
    raw.k32.DisconnectNamedPipe(handle)


def named_pipe_exists(name: str) -> bool:
    """Whether any server is listening on `name`, without connecting to it.

    `WaitNamedPipeW` separates the two cases a plain `open()` conflates:
    ERROR_FILE_NOT_FOUND means there is no such pipe, while ERROR_SEM_TIMEOUT
    means it exists but every instance is currently busy.

    Used by the tests to observe the oracle exiting (a named pipe ceases to
    exist with its server process, which makes this a direct, unambiguous
    signal).
    """
    if raw.k32.WaitNamedPipeW(name, 1):
        return True
    return ctypes.get_last_error() != raw.ERROR_FILE_NOT_FOUND


def named_pipe_client_pid(handle: int) -> int:
    """The pid of the process connected to the server end of `handle`. The
    kernel's own record; the client cannot misreport it."""
    pid = ctypes.wintypes.ULONG()
    if not raw.k32.GetNamedPipeClientProcessId(handle, ctypes.byref(pid)):
        errors.raise_last_error("GetNamedPipeClientProcessId")
    return int(pid.value)


def named_pipe_server_pid(handle: int) -> int:
    """The pid of the process serving the pipe instance `handle` is joined to.
    A client's view of `named_pipe_client_pid`, and equally unforgeable: it is
    the kernel's own record of the pairing, not something the server announced.

    Requires `SECURITY_IDENTIFICATION`-level access to the pipe, which the
    client's `SECURITY_ANONYMOUS` open still grants
    """
    pid = ctypes.wintypes.ULONG()
    if not raw.k32.GetNamedPipeServerProcessId(handle, ctypes.byref(pid)):
        errors.raise_last_error("GetNamedPipeServerProcessId")
    return int(pid.value)


def open_client(name: str) -> int:
    """Open the named pipe `name` for duplex byte I/O, returning a raw HANDLE.

    `ctypes.WinError` maps the code to the right `OSError` subclass, so "no such
    pipe" stays a `FileNotFoundError` and "the DACL says no" stays a
    `PermissionError`, exactly as Python's `open()` reported them. The busy-wait
    retry across instances is the client's, not here.
    """
    handle = raw.k32.CreateFileW(
        name,
        raw.GENERIC_READ | raw.GENERIC_WRITE,
        0,
        None,
        raw.OPEN_EXISTING,
        raw.SECURITY_SQOS_PRESENT | raw.SECURITY_ANONYMOUS,
        None,
    )
    if handle == raw.INVALID_HANDLE_VALUE or not handle:
        raise ctypes.WinError(code=ctypes.get_last_error())
    return handle


def wait_named_pipe(name: str, timeout_ms: int) -> bool:
    """True once an instance of `name` is free, False on timeout. `name` must
    exist for the wait to succeed at all."""
    return bool(raw.k32.WaitNamedPipeW(name, timeout_ms))


def create_inheritable_pipe(size: int = 65536) -> tuple[int, int]:
    """A `(read, write)` anonymous-pipe HANDLE pair; both ends inheritable, so
    the handle list in `spawn.spawn_detached_process` can hand exactly one of
    them to the child."""
    attributes = raw.SECURITY_ATTRIBUTES()
    attributes.nLength = ctypes.sizeof(raw.SECURITY_ATTRIBUTES)
    attributes.lpSecurityDescriptor = None
    attributes.bInheritHandle = True
    read = ctypes.wintypes.HANDLE()
    write = ctypes.wintypes.HANDLE()
    if not raw.k32.CreatePipe(ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), size):
        errors.raise_last_error("CreatePipe")
    return read.value or 0, write.value or 0


def open_nul() -> int:
    """An inheritable HANDLE to `NUL`, to stand in for a child's stdout and
    stderr exactly as `subprocess.DEVNULL` did."""
    attributes = raw.SECURITY_ATTRIBUTES()
    attributes.nLength = ctypes.sizeof(raw.SECURITY_ATTRIBUTES)
    attributes.lpSecurityDescriptor = None
    attributes.bInheritHandle = True
    handle = raw.k32.CreateFileW(
        "NUL",
        raw.GENERIC_READ | raw.GENERIC_WRITE,
        raw.FILE_SHARE_ALL,
        ctypes.byref(attributes),
        raw.OPEN_EXISTING,
        0,
        None,
    )
    if handle == raw.INVALID_HANDLE_VALUE or not handle:
        errors.raise_last_error("CreateFileW(NUL)")
    return handle


def read_file(handle: int, size: int) -> bytes:
    """Blocking read. Returns `b""` when the peer is gone.

    Translating `ERROR_BROKEN_PIPE`/`ERROR_PIPE_NOT_CONNECTED` into an empty
    read is what lets `wire.WireSocket` work unmodified over a pipe.
    """
    buffer = ctypes.create_string_buffer(size)
    transferred = ctypes.wintypes.DWORD()
    if not raw.k32.ReadFile(handle, buffer, size, ctypes.byref(transferred), None):
        if ctypes.get_last_error() in (raw.ERROR_BROKEN_PIPE, raw.ERROR_PIPE_NOT_CONNECTED):
            return b""
        errors.raise_last_error("ReadFile")
    return buffer.raw[: transferred.value]


def write_file(handle: int, data: bytes) -> int:
    """Blocking write. Returns 0 when the peer is gone, for the same reason
    `read_file` returns `b""`."""
    transferred = ctypes.wintypes.DWORD()
    if not raw.k32.WriteFile(handle, data, len(data), ctypes.byref(transferred), None):
        if ctypes.get_last_error() in (raw.ERROR_BROKEN_PIPE, raw.ERROR_NO_DATA, raw.ERROR_PIPE_NOT_CONNECTED):
            return 0
        errors.raise_last_error("WriteFile")
    return int(transferred.value)
