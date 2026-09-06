"""Running `ssh` on Windows, where `pf ssh` cannot simply `execvp` into it.

On POSIX `_ssh_function` ends with `os.execvp("/usr/bin/ssh", ...)`, which
gives three things for free: the `ssh` process *is* the `pf` process (so the
connection oracle's anchor and its peer are the same pid), `ssh` inherits the
mutated environment, and there is nothing left to clean up because there is no
"after".

Windows has none of that. CPython emulates `os.execvp` with `_spawnv`, so
`ssh.exe` would be a child. In this context, a real `Popen` is better than the
emulation, because it lets us put the child in a Job Object: without one, a
`pf` killed abnormally leaves `ssh.exe` running.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import logging
import os
import subprocess

import provablyfine_client as pfc

logger = logging.getLogger(__name__)

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

_JobObjectExtendedLimitInformation = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", ctypes.wintypes.LARGE_INTEGER),
        ("LimitFlags", ctypes.wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.wintypes.DWORD),
        ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
        ("PriorityClass", ctypes.wintypes.DWORD),
        ("SchedulingClass", ctypes.wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.wintypes.LPCWSTR]
_k32.CreateJobObjectW.restype = ctypes.wintypes.HANDLE
_k32.SetInformationJobObject.argtypes = [
    ctypes.wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.wintypes.DWORD,
]
_k32.SetInformationJobObject.restype = ctypes.wintypes.BOOL
_k32.AssignProcessToJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE]
_k32.AssignProcessToJobObject.restype = ctypes.wintypes.BOOL
_k32.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
_k32.OpenProcess.restype = ctypes.wintypes.HANDLE
_k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
_k32.CloseHandle.restype = ctypes.wintypes.BOOL

_PROCESS_SET_QUOTA = 0x0100
_PROCESS_TERMINATE = 0x0001

# Resolved explicitly to avoid interposition attacks.
_SYSTEM32_SSH = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "OpenSSH", "ssh.exe")


def ssh_binary() -> str:
    """The `ssh.exe` to run. Prefers the native OpenSSH build; see above."""
    if os.path.exists(_SYSTEM32_SSH):
        return _SYSTEM32_SSH
    raise pfc.exceptions.UI(
        "No ssh client found. Install the Windows OpenSSH client. "
        'Either run "Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" or '
        "enable it under Settings > System > Optional features > OpenSSH Client."
    )


class _Job:
    """A kill-on-close Job Object.

    Closing the last handle to the job terminates everything still in it, so
    `ssh.exe` cannot outlive `pf`.
    """

    def __init__(self) -> None:
        self.handle = _k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not _k32.SetInformationJobObject(
            self.handle,
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            error = ctypes.get_last_error()
            _k32.CloseHandle(self.handle)
            raise ctypes.WinError(error)

    def assign(self, pid: int) -> None:
        process = _k32.OpenProcess(_PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not _k32.AssignProcessToJobObject(self.handle, process):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _k32.CloseHandle(process)

    def close(self) -> None:
        _k32.CloseHandle(self.handle)


def run_ssh(argv: list[str]) -> None:
    """Run `ssh` to completion and return its exit code."""
    job = _Job()
    try:
        # No env=: `SSH_AUTH_SOCK` is set by mutating `os.environ`, and reaches
        # `ssh.exe` by inheritance exactly as it does through `execvp`. Passing
        # an explicit environment here would silently drop it.
        child = subprocess.Popen(argv, close_fds=True)  # noqa: S603
        logger.debug(f"Started {argv[0]} as pid {child.pid}")
        try:
            job.assign(child.pid)
        except OSError:
            # A race with a child that exited immediately, not a reason to fail
            # the connection: without the job we lose only orphan protection.
            logger.debug("Unable to put ssh in a job object", exc_info=True)
        returncode = child.wait()
        logger.debug(f"ssh exited with {returncode}")
        raise SystemExit(returncode)
    finally:
        job.close()
