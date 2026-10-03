"""Process handles: open, close, observe, and watch for exit.

`OpenProcess` returns a real kernel object reference rather than a recyclable
integer, which is what lets a handle pin one specific process instance and make
the ancestry walk in `peercred` TOCTOU-safe.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes

from .. import exceptions
from . import errors, event, raw


def close_handle(handle: int) -> None:
    """Best-effort close; never raises. Called from `finally` blocks, where a
    failure to close is strictly less interesting than whatever is already
    propagating."""
    raw.k32.CloseHandle(handle)


def open_process(pid: int) -> int | None:
    """A HANDLE to `pid` with just enough access to read its times and image
    and to wait on its exit, or None if it cannot be opened -- already gone, or
    owned by another user."""
    handle = raw.k32.OpenProcess(raw.PROCESS_QUERY_LIMITED_INFORMATION | raw.SYNCHRONIZE, False, pid)
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
        raise exceptions.Error(f"NtQueryInformationProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")
    return int(information.InheritedFromUniqueProcessId or 0)
