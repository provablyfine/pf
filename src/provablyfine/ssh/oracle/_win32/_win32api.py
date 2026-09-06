"""Win32 bindings, via `ctypes`.

Failures raise `ssh.exceptions.Error` carrying `FormatError`'s text, so the
`except (exceptions.Error, OSError)` handlers around the serve loop cover this
module without change.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import dataclasses
import typing

from ... import exceptions

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_adv = ctypes.WinDLL("advapi32", use_last_error=True)
_nt = ctypes.WinDLL("ntdll")

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
# Byte mode (all three zero) is what the ssh-agent protocol wants: it does its
# own length-prefix framing and must not have message boundaries imposed on it.
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_UNLIMITED_INSTANCES = 255

ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_BROKEN_PIPE = 109
ERROR_SEM_TIMEOUT = 121
ERROR_PIPE_BUSY = 231
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_PIPE_CONNECTED = 535

WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000
EVENT_MODIFY_STATE = 0x0002

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200

_TOKEN_QUERY = 0x0008
_TOKEN_USER_CLASS = 1
_SDDL_REVISION_1 = 1


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("nLength", ctypes.wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.wintypes.LPVOID),
        ("bInheritHandle", ctypes.wintypes.BOOL),
    )


class _SidAndAttributes(ctypes.Structure):
    _fields_ = (("Sid", ctypes.wintypes.LPVOID), ("Attributes", ctypes.wintypes.DWORD))


class _TokenUser(ctypes.Structure):
    _fields_ = (("User", _SidAndAttributes),)


class _ProcessBasicInformation(ctypes.Structure):
    """Only the last field is read; the earlier ones exist to place
    `InheritedFromUniqueProcessId` at the right offset."""

    _fields_ = (
        ("ExitStatus", ctypes.wintypes.LPVOID),
        ("PebBaseAddress", ctypes.wintypes.LPVOID),
        ("AffinityMask", ctypes.wintypes.LPVOID),
        ("BasePriority", ctypes.wintypes.LPVOID),
        ("UniqueProcessId", ctypes.wintypes.LPVOID),
        ("InheritedFromUniqueProcessId", ctypes.wintypes.LPVOID),
    )


_LPDWORD = ctypes.POINTER(ctypes.wintypes.DWORD)
_LPFILETIME = ctypes.POINTER(ctypes.wintypes.FILETIME)

_k32.CloseHandle.argtypes = (ctypes.wintypes.HANDLE,)
_k32.CloseHandle.restype = ctypes.wintypes.BOOL
_k32.CreateNamedPipeW.argtypes = (
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
)
_k32.CreateNamedPipeW.restype = ctypes.wintypes.HANDLE
_k32.ConnectNamedPipe.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID)
_k32.ConnectNamedPipe.restype = ctypes.wintypes.BOOL
_k32.DisconnectNamedPipe.argtypes = (ctypes.wintypes.HANDLE,)
_k32.DisconnectNamedPipe.restype = ctypes.wintypes.BOOL
_k32.WaitNamedPipeW.argtypes = (ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD)
_k32.WaitNamedPipeW.restype = ctypes.wintypes.BOOL
_k32.GetNamedPipeClientProcessId.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.ULONG))
_k32.GetNamedPipeClientProcessId.restype = ctypes.wintypes.BOOL
_k32.ReadFile.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    _LPDWORD,
    ctypes.wintypes.LPVOID,
)
_k32.ReadFile.restype = ctypes.wintypes.BOOL
_k32.WriteFile.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.wintypes.DWORD,
    _LPDWORD,
    ctypes.wintypes.LPVOID,
)
_k32.WriteFile.restype = ctypes.wintypes.BOOL
_k32.CreateEventW.argtypes = (
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.wintypes.BOOL,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.LPCWSTR,
)
_k32.CreateEventW.restype = ctypes.wintypes.HANDLE
_k32.OpenEventW.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR)
_k32.OpenEventW.restype = ctypes.wintypes.HANDLE
_k32.SetEvent.argtypes = (ctypes.wintypes.HANDLE,)
_k32.SetEvent.restype = ctypes.wintypes.BOOL
_k32.ResetEvent.argtypes = (ctypes.wintypes.HANDLE,)
_k32.ResetEvent.restype = ctypes.wintypes.BOOL
_k32.WaitForSingleObject.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD)
_k32.WaitForSingleObject.restype = ctypes.wintypes.DWORD
_k32.WaitForMultipleObjects.argtypes = (
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
)
_k32.WaitForMultipleObjects.restype = ctypes.wintypes.DWORD
_k32.OpenProcess.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
_k32.OpenProcess.restype = ctypes.wintypes.HANDLE
_k32.GetCurrentProcess.argtypes = ()
_k32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
_k32.GetProcessTimes.argtypes = (ctypes.wintypes.HANDLE, _LPFILETIME, _LPFILETIME, _LPFILETIME, _LPFILETIME)
_k32.GetProcessTimes.restype = ctypes.wintypes.BOOL
_k32.QueryFullProcessImageNameW.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPWSTR,
    _LPDWORD,
)
_k32.QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL
_k32.ProcessIdToSessionId.argtypes = (ctypes.wintypes.DWORD, _LPDWORD)
_k32.ProcessIdToSessionId.restype = ctypes.wintypes.BOOL
_k32.LocalFree.argtypes = (ctypes.wintypes.HLOCAL,)
_k32.LocalFree.restype = ctypes.wintypes.HLOCAL

_adv.OpenProcessToken.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
)
_adv.OpenProcessToken.restype = ctypes.wintypes.BOOL
_adv.GetTokenInformation.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_int,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    _LPDWORD,
)
_adv.GetTokenInformation.restype = ctypes.wintypes.BOOL
_adv.ConvertSidToStringSidW.argtypes = (ctypes.wintypes.LPVOID, ctypes.POINTER(ctypes.wintypes.LPWSTR))
_adv.ConvertSidToStringSidW.restype = ctypes.wintypes.BOOL
_adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.LPVOID),
    _LPDWORD,
)
_adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.wintypes.BOOL

# Undocumented, but unchanged since NT 4 and relied on by essentially every
# process-tree tool on Windows. The public alternative,
# `CreateToolhelp32Snapshot`, only reports a parent *pid* read out of a
# whole-system snapshot; this one answers for a HANDLE we already hold, which
# is exactly what makes `peercred.is_descendant_of`'s walk TOCTOU-safe.
_nt.NtQueryInformationProcess.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_int,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.ULONG,
    _LPDWORD,
)
_nt.NtQueryInformationProcess.restype = ctypes.c_long


def last_error_message(prefix: str) -> str:
    code = ctypes.get_last_error()
    return f"{prefix}: [{code}] {ctypes.FormatError(code)}"


def raise_last_error(prefix: str) -> typing.NoReturn:
    raise exceptions.Error(last_error_message(prefix))


def close_handle(handle: int) -> None:
    """Best-effort close; never raises. Called from `finally` blocks, where a
    failure to close is strictly less interesting than whatever is already
    propagating."""
    _k32.CloseHandle(handle)


@dataclasses.dataclass(frozen=True)
class OwnedSecurityAttributes:
    """A `SECURITY_ATTRIBUTES` bundled with the descriptor it points at.

    `lpSecurityDescriptor` is a bare pointer into a `LocalAlloc`'d block. With
    nothing holding a Python reference to that block it would be collected
    while the kernel still had the pointer, so the two have to travel together.
    Callers pass `.attributes` and keep the holder alive across the call.
    """

    attributes: SECURITY_ATTRIBUTES
    descriptor: ctypes.wintypes.LPVOID = dataclasses.field(repr=False)


def _current_user_sid_string() -> str:
    process_token = ctypes.wintypes.HANDLE()
    if not _adv.OpenProcessToken(_k32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(process_token)):
        raise_last_error("OpenProcessToken")
    try:
        size = ctypes.wintypes.DWORD()
        _adv.GetTokenInformation(process_token, _TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
        # The SID lives *inside* this buffer, so it has to stay alive across
        # the ConvertSidToStringSidW call below.
        buffer = ctypes.create_string_buffer(size.value)
        if not _adv.GetTokenInformation(process_token, _TOKEN_USER_CLASS, buffer, size, ctypes.byref(size)):
            raise_last_error("GetTokenInformation")
        token_user = ctypes.cast(buffer, ctypes.POINTER(_TokenUser)).contents
        string_sid = ctypes.wintypes.LPWSTR()
        if not _adv.ConvertSidToStringSidW(token_user.User.Sid, ctypes.byref(string_sid)):
            raise_last_error("ConvertSidToStringSidW")
        try:
            return string_sid.value or ""
        finally:
            _k32.LocalFree(ctypes.cast(string_sid, ctypes.wintypes.HLOCAL))
    finally:
        close_handle(process_token.value or 0)


def owner_only_security_attributes(*, inheritable: bool) -> OwnedSecurityAttributes:
    """Security attributes granting full access to this user and SYSTEM only.

    A UNIX socket inherits the protection of the directory holding it, which is
    what `.._posix.spawn` relies on with its 0700 directory. `\\\\.\\pipe\\` is a
    flat, machine-global namespace with no directory to hide behind, so the
    restriction has to be stated on the object itself.

    Like its POSIX counterpart this is belt-and-braces: the real boundary is
    the peer-credential check at accept().
    """
    sid = _current_user_sid_string()
    sddl = f"O:{sid}G:{sid}D:(A;;GA;;;{sid})(A;;GA;;;SY)"
    descriptor = ctypes.wintypes.LPVOID()
    if not _adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        raise_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    attributes = SECURITY_ATTRIBUTES()
    attributes.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    attributes.lpSecurityDescriptor = descriptor
    attributes.bInheritHandle = inheritable
    return OwnedSecurityAttributes(attributes=attributes, descriptor=descriptor)


def create_named_pipe(name: str, *, inheritable: bool) -> int:
    """Create the listening pipe, refusing to become a *second* instance.

    `FILE_FLAG_FIRST_PIPE_INSTANCE` is what turns "someone already claimed this
    name" from a silent compromise into a loud failure: without it we would
    cheerfully add an instance alongside a squatter's, and clients would reach
    whichever happened to be pending.
    """
    handle = try_create_named_pipe(name, inheritable=inheritable)
    if handle is None:
        raise_last_error(f"CreateNamedPipeW({name})")
    return handle


def try_create_named_pipe(name: str, *, inheritable: bool) -> int | None:
    """`create_named_pipe`, returning None instead of raising when the name is
    already taken.

    Separate from the raising version so the new-login retry loop in
    `session.py` can tell "wait, the predecessor still holds it" apart from a
    real failure, instead of retrying blindly on any error.
    `ERROR_ACCESS_DENIED` is what FIRST_PIPE_INSTANCE reports for a name that
    already exists.
    """
    security = owner_only_security_attributes(inheritable=inheritable)
    handle = _k32.CreateNamedPipeW(
        name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES,
        65536,
        65536,
        0,
        ctypes.byref(security.attributes),
    )
    if handle == INVALID_HANDLE_VALUE or not handle:
        if ctypes.get_last_error() in (ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY):
            return None
        raise_last_error(f"CreateNamedPipeW({name})")
    return handle


def connect_named_pipe(handle: int) -> None:
    """Block until a client connects.

    `ERROR_PIPE_CONNECTED` is success, not failure: it means a client got in
    during the window between the pipe being created (or disconnected) and this
    call. That is routine -- it was in fact what the spawn prototype hit every
    single time.
    """
    if _k32.ConnectNamedPipe(handle, None):
        return
    if ctypes.get_last_error() == ERROR_PIPE_CONNECTED:
        return
    raise_last_error("ConnectNamedPipe")


def disconnect_named_pipe(handle: int) -> None:
    _k32.DisconnectNamedPipe(handle)


def named_pipe_exists(name: str) -> bool:
    """Whether any server is listening on `name`, without connecting to it.

    `WaitNamedPipeW` separates the two cases a plain `open()` conflates:
    ERROR_FILE_NOT_FOUND means there is no such pipe, while ERROR_SEM_TIMEOUT
    means it exists but every instance is currently busy.

    Used by the tests to observe the oracle exiting (a named pipe ceases to
    exist with its server process, which makes this a direct, unambiguous
    signal).
    """
    if _k32.WaitNamedPipeW(name, 1):
        return True
    return ctypes.get_last_error() != ERROR_FILE_NOT_FOUND


def named_pipe_client_pid(handle: int) -> int:
    pid = ctypes.wintypes.ULONG()
    if not _k32.GetNamedPipeClientProcessId(handle, ctypes.byref(pid)):
        raise_last_error("GetNamedPipeClientProcessId")
    return int(pid.value)


def read_file(handle: int, size: int) -> bytes:
    """Blocking read. Returns `b""` when the peer is gone.

    Translating `ERROR_BROKEN_PIPE`/`ERROR_PIPE_NOT_CONNECTED` into an empty
    read is what lets `wire.WireSocket` work unmodified over a pipe.
    """
    buffer = ctypes.create_string_buffer(size)
    transferred = ctypes.wintypes.DWORD()
    if not _k32.ReadFile(handle, buffer, size, ctypes.byref(transferred), None):
        if ctypes.get_last_error() in (ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED):
            return b""
        raise_last_error("ReadFile")
    return buffer.raw[: transferred.value]


def write_file(handle: int, data: bytes) -> int:
    """Blocking write. Returns 0 when the peer is gone, for the same reason
    `read_file` returns `b""`."""
    transferred = ctypes.wintypes.DWORD()
    if not _k32.WriteFile(handle, data, len(data), ctypes.byref(transferred), None):
        if ctypes.get_last_error() in (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED):
            return 0
        raise_last_error("WriteFile")
    return int(transferred.value)


def create_event(name: str) -> int:
    """A named, manual-reset event.

    Manual-reset because the watchdog waits on it once and must see it stay
    signaled. Note `CreateEventW` on an existing name *opens* that event rather
    than making a new one -- callers must `reset_event()` immediately after, or
    a predecessor's still-signaled event fires the new watchdog instantly.
    """
    handle = _k32.CreateEventW(None, True, False, name)
    if not handle:
        raise_last_error(f"CreateEventW({name})")
    return handle


def open_event(name: str) -> int | None:
    """Open an existing named event, or None if there is no such event."""
    handle = _k32.OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, False, name)
    return None if not handle else handle


def set_event(handle: int) -> None:
    if not _k32.SetEvent(handle):
        raise_last_error("SetEvent")


def reset_event(handle: int) -> None:
    if not _k32.ResetEvent(handle):
        raise_last_error("ResetEvent")


def wait_for_single_object(handle: int, timeout_ms: int) -> int:
    result = _k32.WaitForSingleObject(handle, timeout_ms)
    if result == WAIT_FAILED:
        raise_last_error("WaitForSingleObject")
    return int(result)


def wait_for_any(handles: tuple[int, ...], timeout_ms: int) -> int | None:
    """Wait until any of `handles` is signaled; return its index, or None on
    timeout."""
    array = (ctypes.wintypes.HANDLE * len(handles))(*handles)
    result = _k32.WaitForMultipleObjects(len(handles), array, False, timeout_ms)
    if result == WAIT_TIMEOUT:
        return None
    if result == WAIT_FAILED:
        raise_last_error("WaitForMultipleObjects")
    index = int(result) - WAIT_OBJECT_0
    if not 0 <= index < len(handles):
        raise exceptions.Error(f"WaitForMultipleObjects returned an unexpected result: {result}")
    return index


def open_process(pid: int) -> int | None:
    """A HANDLE to `pid` with just enough access to read its times and image
    and to wait on its exit, or None if it cannot be opened -- already gone, or
    owned by another user."""
    handle = _k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
    return None if not handle else handle


def process_creation_time(handle: int) -> int:
    """The process's creation time as one 64-bit int.

    The Windows analogue of Darwin's `start_key` and Linux's
    `/proc/<pid>/stat` field 22: paired with the pid it identifies one specific
    process instance, so a recycled pid gets a different value.
    """
    created = ctypes.wintypes.FILETIME()
    unused = ctypes.wintypes.FILETIME()
    ok = _k32.GetProcessTimes(
        handle, ctypes.byref(created), ctypes.byref(unused), ctypes.byref(unused), ctypes.byref(unused)
    )
    if not ok:
        raise_last_error("GetProcessTimes")
    return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)


def process_image_path(handle: int) -> str:
    size = ctypes.wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not _k32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
        raise_last_error("QueryFullProcessImageNameW")
    return buffer.value


def process_parent_pid(handle: int) -> int:
    information = _ProcessBasicInformation()
    returned = ctypes.wintypes.DWORD()
    status = _nt.NtQueryInformationProcess(
        handle, 0, ctypes.byref(information), ctypes.sizeof(information), ctypes.byref(returned)
    )
    if status != 0:
        raise exceptions.Error(f"NtQueryInformationProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
    return int(information.InheritedFromUniqueProcessId or 0)


def process_session_id(pid: int) -> int | None:
    session_id = ctypes.wintypes.DWORD()
    if not _k32.ProcessIdToSessionId(pid, ctypes.byref(session_id)):
        return None
    return int(session_id.value)
