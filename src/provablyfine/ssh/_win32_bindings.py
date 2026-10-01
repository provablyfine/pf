"""Raw Win32 bindings shared by the ssh-agent client and the signing oracle."""

from __future__ import annotations

import ctypes
import ctypes.wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3

# https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_ANONYMOUS = 0x00000000


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("nLength", ctypes.wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.wintypes.LPVOID),
        ("bInheritHandle", ctypes.wintypes.BOOL),
    )


k32.CreateFileW.argtypes = (
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.HANDLE,
)
k32.CreateFileW.restype = ctypes.wintypes.HANDLE
k32.WaitNamedPipeW.argtypes = (ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD)
k32.WaitNamedPipeW.restype = ctypes.wintypes.BOOL
