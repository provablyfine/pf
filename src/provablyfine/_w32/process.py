"""Process handles: open, close, observe, and watch for exit.

`OpenProcess` returns a real kernel object reference rather than a recyclable
integer
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import dataclasses

from .. import ssh
from . import errors, event, raw


def close_handle(handle: int) -> None:
    """Best-effort close; never raises. Called from `finally` blocks, where a
    failure to close is strictly less interesting than whatever is already
    propagating."""
    raw.k32.CloseHandle(handle)


def open_process(pid: int, access: int = raw.PROCESS_QUERY_LIMITED_INFORMATION | raw.SYNCHRONIZE) -> int | None:
    """A HANDLE to `pid`, or None if it cannot be opened (already gone, or
    owned by another user).

    The default access is just enough to read its times and image and to wait
    on its exit. A caller that must see processes of other users, such as
    SYSTEM, passes less: asking for `SYNCHRONIZE` can be refused.
    """
    handle = raw.k32.OpenProcess(access, False, pid)
    return None if not handle else handle


def try_open_process_for_read(pid: int) -> tuple[int | None, int]:
    """`(handle, 0)` or `(None, error)`, trying the access a memory-reading
    tool needs. Exists so tests can verify what a process DACL promises is
    actually enforced; nothing in production uses it."""
    access = raw.PROCESS_VM_READ | raw.PROCESS_VM_OPERATION | raw.PROCESS_CREATE_THREAD | raw.PROCESS_SUSPEND_RESUME
    handle = raw.k32.OpenProcess(access, False, pid)
    if handle:
        return handle, 0
    return None, ctypes.get_last_error()


def current_process_handle() -> int:
    return raw.k32.GetCurrentProcess()


def is_alive(handle: int) -> bool:
    """True while the process pinned by `handle` is still running.

    A process HANDLE signals once at exit and stays signaled, so a zero-timeout
    wait reports liveness without blocking.
    """
    return event.wait_for_single_object(handle, 0) == raw.WAIT_TIMEOUT


def process_creation_time(handle: int) -> int:
    """The process's creation time as one 64-bit int.

    The Windows analogue of Darwin's `start_key` and Linux's
    `/proc/<pid>/stat` field 22: paired with the pid it identifies one specific
    process instance, so a recycled pid gets a different value.
    """
    created = ctypes.wintypes.FILETIME()
    unused = ctypes.wintypes.FILETIME()
    ok = raw.k32.GetProcessTimes(
        handle, ctypes.byref(created), ctypes.byref(unused), ctypes.byref(unused), ctypes.byref(unused)
    )
    if not ok:
        errors.raise_last_error("GetProcessTimes")
    return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)


def process_image_path(handle: int) -> str:
    size = ctypes.wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(size.value)
    if not raw.k32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
        errors.raise_last_error("QueryFullProcessImageNameW")
    return buffer.value


def process_parent_pid(handle: int) -> int:
    """The parent pid of the process `handle` refers to, read through that
    handle so a recycled pid cannot answer for a different process.

    `NtQueryInformationProcess` is undocumented but unchanged since NT 4. The
    public alternative, `CreateToolhelp32Snapshot`, reports a parent pid only
    from a whole-system snapshot, which is racy for this walk.
    """
    information = raw.PROCESS_BASIC_INFORMATION()
    returned = ctypes.wintypes.DWORD()
    status = raw.nt.NtQueryInformationProcess(
        handle, 0, ctypes.byref(information), ctypes.sizeof(information), ctypes.byref(returned)
    )
    if status != 0:
        raise ssh.exceptions.Error(f"NtQueryInformationProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
    return int(information.InheritedFromUniqueProcessId or 0)


@dataclasses.dataclass(frozen=True)
class ProcessEntry:
    pid: int
    parent_pid: int
    image_name: str


def snapshot() -> list[ProcessEntry]:
    """Every process on the machine, from one Toolhelp snapshot.

    A snapshot lists processes of other users too, SYSTEM included, which
    WMI does not show to a standard user. It is a list of facts that may be
    stale by the time it is read. To learn about a process we already hold a
    HANDLE to, use `process_parent_pid` instead.
    """
    handle = raw.k32.CreateToolhelp32Snapshot(raw.TH32CS_SNAPPROCESS, 0)
    if handle is None or handle == raw.INVALID_HANDLE_VALUE:
        errors.raise_last_error("CreateToolhelp32Snapshot")
    entries: list[ProcessEntry] = []
    try:
        entry = raw.PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(raw.PROCESSENTRY32W)
        found = raw.k32.Process32FirstW(handle, ctypes.byref(entry))
        while found:
            entries.append(ProcessEntry(entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile))
            found = raw.k32.Process32NextW(handle, ctypes.byref(entry))
        if ctypes.get_last_error() not in (0, raw.ERROR_NO_MORE_FILES):
            errors.raise_last_error("Process32NextW")
    finally:
        close_handle(handle)
    return entries


def terminate(pid: int) -> None:
    """End the process `pid`. Windows has no gentle request.

    A process that is already gone is not an error: that is the outcome we
    wanted.
    """
    handle = open_process(pid, raw.PROCESS_TERMINATE | raw.PROCESS_QUERY_LIMITED_INFORMATION)
    if handle is None:
        error = ctypes.get_last_error()
        if error == raw.ERROR_INVALID_PARAMETER:
            return
        errors.raise_last_error("OpenProcess")
    try:
        if raw.k32.TerminateProcess(handle, 1):
            return
        error = ctypes.get_last_error()
        # A process that has ended can still be opened while another process
        # holds a handle to it. Ending it again is refused, which is fine.
        code = ctypes.wintypes.DWORD()
        if raw.k32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != raw.STILL_ACTIVE:
            return
        ctypes.set_last_error(error)
        errors.raise_last_error("TerminateProcess")
    finally:
        close_handle(handle)
