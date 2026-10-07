"""Raw Win32 bindings, via `ctypes`.

Only the OS surface lives here: DLL handles, structures, constants, and
`argtypes`/`restype`, each named for the Win32 function it wraps.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

# ntdll for the one call the public Toolhelp snapshot cannot answer for a HANDLE
# we already hold, which is what makes the ancestry walk TOCTOU-safe.
nt = ctypes.WinDLL("ntdll")

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_ALL = 0x00000007

# https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_ANONYMOUS = 0x00000000

# Named-pipe create flags and modes.
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
ERROR_NO_MORE_FILES = 18
ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
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
PROCESS_TERMINATE = 0x0001
STILL_ACTIVE = 259
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
PROCESS_VM_READ = 0x0010
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SUSPEND_RESUME = 0x0800
SYNCHRONIZE = 0x00100000
EVENT_MODIFY_STATE = 0x0002

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002

# `WerSetFlags` bits, so a crash can't hand WerFault a reason to write a
# user-readable dump of our address space (HKCU `LocalDumps` included).
WER_FAULT_REP_DISABLE = 0x00000002
WER_DEBUG_INFO_DISABLE = 0x00000004
WER_UI_DISABLE = 0x00000010

TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_USER_CLASS = 1
TOKEN_LOGON_SID_CLASS = 28
SDDL_REVISION_1 = 1


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("nLength", ctypes.wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.wintypes.LPVOID),
        ("bInheritHandle", ctypes.wintypes.BOOL),
    )


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = (("Sid", ctypes.wintypes.LPVOID), ("Attributes", ctypes.wintypes.DWORD))


class TOKEN_USER(ctypes.Structure):
    _fields_ = (("User", SID_AND_ATTRIBUTES),)


class TOKEN_GROUPS(ctypes.Structure):
    # `TokenLogonSid` returns exactly one group, so a length-1 array is enough.
    _fields_ = (("GroupCount", ctypes.wintypes.DWORD), ("Groups", SID_AND_ATTRIBUTES * 1))


class LUID(ctypes.Structure):
    _fields_ = (("LowPart", ctypes.wintypes.DWORD), ("HighPart", ctypes.wintypes.LONG))


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = (("Luid", LUID), ("Attributes", ctypes.wintypes.DWORD))


class TOKEN_PRIVILEGES(ctypes.Structure):
    # `disable_debug_privilege` adjusts exactly one, so a length-1 array suffices.
    _fields_ = (("PrivilegeCount", ctypes.wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1))


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
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


class STARTUPINFOW(ctypes.Structure):
    _fields_ = (
        ("cb", ctypes.wintypes.DWORD),
        ("lpReserved", ctypes.wintypes.LPWSTR),
        ("lpDesktop", ctypes.wintypes.LPWSTR),
        ("lpTitle", ctypes.wintypes.LPWSTR),
        ("dwX", ctypes.wintypes.DWORD),
        ("dwY", ctypes.wintypes.DWORD),
        ("dwXSize", ctypes.wintypes.DWORD),
        ("dwYSize", ctypes.wintypes.DWORD),
        ("dwXCountChars", ctypes.wintypes.DWORD),
        ("dwYCountChars", ctypes.wintypes.DWORD),
        ("dwFillAttribute", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("wShowWindow", ctypes.wintypes.WORD),
        ("cbReserved2", ctypes.wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_char)),
        ("hStdInput", ctypes.wintypes.HANDLE),
        ("hStdOutput", ctypes.wintypes.HANDLE),
        ("hStdError", ctypes.wintypes.HANDLE),
    )


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = (
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", ctypes.wintypes.LPVOID),
    )


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("hProcess", ctypes.wintypes.HANDLE),
        ("hThread", ctypes.wintypes.HANDLE),
        ("dwProcessId", ctypes.wintypes.DWORD),
        ("dwThreadId", ctypes.wintypes.DWORD),
    )


class PROCESSENTRY32W(ctypes.Structure):
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
        ("szExeFile", ctypes.wintypes.WCHAR * MAX_PATH),
    )


_LPDWORD = ctypes.POINTER(ctypes.wintypes.DWORD)
_LPFILETIME = ctypes.POINTER(ctypes.wintypes.FILETIME)

k32.CloseHandle.argtypes = (ctypes.wintypes.HANDLE,)
k32.CloseHandle.restype = ctypes.wintypes.BOOL
k32.CreateToolhelp32Snapshot.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.DWORD)
k32.CreateToolhelp32Snapshot.restype = ctypes.wintypes.HANDLE
k32.CreateEventW.argtypes = (
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.wintypes.BOOL,
    ctypes.wintypes.BOOL,
    ctypes.wintypes.LPCWSTR,
)
k32.CreateEventW.restype = ctypes.wintypes.HANDLE
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
k32.CreateNamedPipeW.argtypes = (
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
)
k32.CreateNamedPipeW.restype = ctypes.wintypes.HANDLE
k32.CreatePipe.argtypes = (
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.wintypes.DWORD,
)
k32.CreatePipe.restype = ctypes.wintypes.BOOL
k32.CreateProcessW.argtypes = (
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.LPWSTR,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
)
k32.CreateProcessW.restype = ctypes.wintypes.BOOL
k32.ConnectNamedPipe.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID)
k32.ConnectNamedPipe.restype = ctypes.wintypes.BOOL
k32.DeleteProcThreadAttributeList.argtypes = (ctypes.wintypes.LPVOID,)
k32.DeleteProcThreadAttributeList.restype = None
k32.DisconnectNamedPipe.argtypes = (ctypes.wintypes.HANDLE,)
k32.DisconnectNamedPipe.restype = ctypes.wintypes.BOOL
k32.GetCurrentProcess.argtypes = ()
k32.GetCurrentProcess.restype = ctypes.wintypes.HANDLE
k32.GetExitCodeProcess.argtypes = (ctypes.wintypes.HANDLE, _LPDWORD)
k32.GetExitCodeProcess.restype = ctypes.wintypes.BOOL
k32.GetNamedPipeClientProcessId.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.ULONG))
k32.GetNamedPipeClientProcessId.restype = ctypes.wintypes.BOOL
k32.GetNamedPipeServerProcessId.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.ULONG))
k32.GetNamedPipeServerProcessId.restype = ctypes.wintypes.BOOL
k32.GetProcessTimes.argtypes = (ctypes.wintypes.HANDLE, _LPFILETIME, _LPFILETIME, _LPFILETIME, _LPFILETIME)
k32.GetProcessTimes.restype = ctypes.wintypes.BOOL
k32.InitializeProcThreadAttributeList.argtypes = (
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    _LPDWORD,
)
k32.InitializeProcThreadAttributeList.restype = ctypes.wintypes.BOOL
k32.LocalFree.argtypes = (ctypes.wintypes.HLOCAL,)
k32.LocalFree.restype = ctypes.wintypes.HLOCAL
k32.OpenEventW.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.LPCWSTR)
k32.OpenEventW.restype = ctypes.wintypes.HANDLE
k32.OpenProcess.argtypes = (ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD)
k32.OpenProcess.restype = ctypes.wintypes.HANDLE
k32.Process32FirstW.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
k32.Process32FirstW.restype = ctypes.wintypes.BOOL
k32.Process32NextW.argtypes = (ctypes.wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
k32.Process32NextW.restype = ctypes.wintypes.BOOL
k32.QueryFullProcessImageNameW.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPWSTR,
    _LPDWORD,
)
k32.QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL
k32.ReadFile.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    _LPDWORD,
    ctypes.wintypes.LPVOID,
)
k32.ReadFile.restype = ctypes.wintypes.BOOL
k32.ResetEvent.argtypes = (ctypes.wintypes.HANDLE,)
k32.ResetEvent.restype = ctypes.wintypes.BOOL
k32.SetEvent.argtypes = (ctypes.wintypes.HANDLE,)
k32.SetEvent.restype = ctypes.wintypes.BOOL
k32.TerminateProcess.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.UINT)
k32.TerminateProcess.restype = ctypes.wintypes.BOOL
k32.UpdateProcThreadAttribute.argtypes = (
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.DWORD,
    ctypes.wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.wintypes.LPVOID,
    ctypes.POINTER(ctypes.c_size_t),
)
k32.UpdateProcThreadAttribute.restype = ctypes.wintypes.BOOL
k32.WaitNamedPipeW.argtypes = (ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD)
k32.WaitNamedPipeW.restype = ctypes.wintypes.BOOL
k32.WaitForMultipleObjects.argtypes = (
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
    ctypes.wintypes.BOOL,
    ctypes.wintypes.DWORD,
)
k32.WaitForMultipleObjects.restype = ctypes.wintypes.DWORD
k32.WaitForSingleObject.argtypes = (ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD)
k32.WaitForSingleObject.restype = ctypes.wintypes.DWORD
k32.WriteFile.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.LPCVOID,
    ctypes.wintypes.DWORD,
    _LPDWORD,
    ctypes.wintypes.LPVOID,
)
k32.WriteFile.restype = ctypes.wintypes.BOOL

adv.AdjustTokenPrivileges.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.BOOL,
    ctypes.POINTER(TOKEN_PRIVILEGES),
    ctypes.wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
)
adv.AdjustTokenPrivileges.restype = ctypes.wintypes.BOOL
adv.ConvertSidToStringSidW.argtypes = (ctypes.wintypes.LPVOID, ctypes.POINTER(ctypes.wintypes.LPWSTR))
adv.ConvertSidToStringSidW.restype = ctypes.wintypes.BOOL
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
    ctypes.wintypes.LPCWSTR,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.LPVOID),
    _LPDWORD,
)
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.wintypes.BOOL
adv.GetTokenInformation.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_int,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.DWORD,
    _LPDWORD,
)
adv.GetTokenInformation.restype = ctypes.wintypes.BOOL
adv.LookupPrivilegeValueW.argtypes = (ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR, ctypes.POINTER(LUID))
adv.LookupPrivilegeValueW.restype = ctypes.wintypes.BOOL
adv.OpenProcessToken.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.HANDLE),
)
adv.OpenProcessToken.restype = ctypes.wintypes.BOOL

nt.NtQueryInformationProcess.argtypes = (
    ctypes.wintypes.HANDLE,
    ctypes.c_int,
    ctypes.wintypes.LPVOID,
    ctypes.wintypes.ULONG,
    _LPDWORD,
)
nt.NtQueryInformationProcess.restype = ctypes.c_long

shell32.IsUserAnAdmin.argtypes = ()
shell32.IsUserAnAdmin.restype = ctypes.wintypes.BOOL
