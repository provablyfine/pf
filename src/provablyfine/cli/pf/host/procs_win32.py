"""The process table on Windows.

This reads Toolhelp snapshots. WMI would not do: a standard user cannot see the
processes that belong to SYSTEM, and the principals command runs as a standard
user below an sshd that belongs to SYSTEM. A snapshot lists every process.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes

from . import procs

_TH32CS_SNAPPROCESS = 0x2
_PROCESS_TERMINATE = 0x1
_STILL_ACTIVE = 259
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_INVALID_PARAMETER = 87
_ERROR_NO_MORE_FILES = 18
_FILETIME_UNIX_EPOCH = 116444736000000000


class _ProcessEntry(ctypes.Structure):
    _fields_ = (
        ("dwSize", ctypes.wintypes.DWORD),
        ("cntUsage", ctypes.wintypes.DWORD),
        ("th32ProcessID", ctypes.wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.wintypes.DWORD),
        ("cntThreads", ctypes.wintypes.DWORD),
        ("th32ParentProcessID", ctypes.wintypes.DWORD),
        ("pcPriClassBase", ctypes.wintypes.LONG),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("szExeFile", ctypes.wintypes.WCHAR * 260),
    )


_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_kernel32.CreateToolhelp32Snapshot.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.DWORD)
_kernel32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
_kernel32.Process32FirstW.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(_ProcessEntry))
_kernel32.Process32FirstW.restype = ctypes.wintypes.BOOL
_kernel32.Process32NextW.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(_ProcessEntry))
_kernel32.Process32NextW.restype = ctypes.wintypes.BOOL
_kernel32.OpenProcess.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
_kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
_kernel32.GetProcessTimes.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.POINTER(ctypes.wintypes.FILETIME),
    ctypes.POINTER(ctypes.wintypes.FILETIME),
    ctypes.POINTER(ctypes.wintypes.FILETIME),
    ctypes.POINTER(ctypes.wintypes.FILETIME),
)
_kernel32.GetProcessTimes.restype = ctypes.wintypes.BOOL
_kernel32.TerminateProcess.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.UINT)
_kernel32.TerminateProcess.restype = ctypes.wintypes.BOOL
_kernel32.GetExitCodeProcess.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD))
_kernel32.GetExitCodeProcess.restype = ctypes.wintypes.BOOL
_kernel32.CloseHandle.argtypes = (ctypes.wintypes.HANDLE,)
_kernel32.CloseHandle.restype = ctypes.wintypes.BOOL


def _filetime_to_unix_seconds(value: ctypes.wintypes.FILETIME) -> int:
    ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
    return (ticks - _FILETIME_UNIX_EPOCH) // 10_000_000


class Win32Table:
    def snapshot(self) -> procs.Snapshot:
        handle = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        if handle is None or handle == ctypes.wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        table: procs.Snapshot = {}
        try:
            entry = _ProcessEntry()
            entry.dwSize = ctypes.sizeof(_ProcessEntry)
            found = _kernel32.Process32FirstW(handle, ctypes.byref(entry))
            while found:
                table[entry.th32ProcessID] = procs.Proc(entry.th32ProcessID, entry.th32ParentProcessID, entry.szExeFile)
                found = _kernel32.Process32NextW(handle, ctypes.byref(entry))
            if ctypes.get_last_error() not in (0, _ERROR_NO_MORE_FILES):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _kernel32.CloseHandle(handle)
        return table

    def start_time(self, pid: int) -> int | None:
        handle = _kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None
        try:
            created, exited, kernel, user = (ctypes.wintypes.FILETIME() for _ in range(4))
            ok = _kernel32.GetProcessTimes(
                handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)
            )
            return _filetime_to_unix_seconds(created) if ok else None
        finally:
            _kernel32.CloseHandle(handle)

    def send_signal(self, pid: int, *, force: bool) -> None:
        """End the process. Windows has no gentle request, so `force` makes no difference."""
        handle = _kernel32.OpenProcess(_PROCESS_TERMINATE | _PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == _ERROR_INVALID_PARAMETER:
                # There is no such process any more.
                return
            raise ctypes.WinError(error)
        try:
            if _kernel32.TerminateProcess(handle, 1):
                return
            error = ctypes.get_last_error()
            # A process that has ended can still be opened while another process holds a handle to it.
            # Ending it again is refused. That is the outcome we wanted.
            code = ctypes.wintypes.DWORD()
            if _kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != _STILL_ACTIVE:
                return
            raise ctypes.WinError(error)
        finally:
            _kernel32.CloseHandle(handle)
