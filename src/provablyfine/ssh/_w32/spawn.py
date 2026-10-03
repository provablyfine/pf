"""`CreateProcessW` with an explicit handle list and a process-object DACL.

The mechanism only: the caller supplies the child process object's security
descriptor (`process_security`) and the exact handles to inherit. Locking the
key out of reach is the oracle's policy for what descriptor to pass, not this
function's.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes

from . import errors, process, raw, security


def spawn_detached_process(
    command_line: str,
    *,
    inherit: tuple[int, ...],
    std_input: int,
    std_null: int,
    process_security: security.OwnedSecurityAttributes,
) -> int:
    """`CreateProcessW` a detached, new-process-group child, and return its pid.

    Only the handles in `inherit` (plus `std_input` and `std_null`, which the
    child receives as its std handles) reach the child:
    `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` suppresses the default "everything
    inheritable leaks" inheritance, same job `close_fds=True` did for
    `subprocess.Popen`. `process_security` is the child *process object's* DACL
    from its first instant.
    """
    size = ctypes.wintypes.DWORD()
    # First call must fail with ERROR_INSUFFICIENT_BUFFER and return the size.
    if raw.k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size)) or not size.value:
        errors.raise_last_error("InitializeProcThreadAttributeList")
    storage = ctypes.create_string_buffer(size.value)
    attribute_list = ctypes.cast(storage, ctypes.wintypes.LPVOID)
    if not raw.k32.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(size)):
        errors.raise_last_error("InitializeProcThreadAttributeList")
    handles = (ctypes.wintypes.HANDLE * len(inherit))(*inherit)
    try:
        if not raw.k32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            raw.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.cast(handles, ctypes.wintypes.LPVOID),
            ctypes.sizeof(handles),
            None,
            None,
        ):
            errors.raise_last_error("UpdateProcThreadAttribute")
        startup = raw.STARTUPINFOEXW()
        startup.StartupInfo.cb = ctypes.sizeof(raw.STARTUPINFOEXW)
        startup.StartupInfo.dwFlags = raw.STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = std_input
        startup.StartupInfo.hStdOutput = std_null
        startup.StartupInfo.hStdError = std_null
        startup.lpAttributeList = attribute_list
        info = raw.PROCESS_INFORMATION()
        command = ctypes.create_unicode_buffer(command_line)
        flags = raw.EXTENDED_STARTUPINFO_PRESENT | raw.DETACHED_PROCESS | raw.CREATE_NEW_PROCESS_GROUP
        if not raw.k32.CreateProcessW(
            None,
            command,
            ctypes.byref(process_security.attributes),
            None,
            True,
            flags,
            None,
            None,
            # `byref` of the embedded member: ctypes enforces the declared
            # `POINTER(STARTUPINFOW)`, and the member is at offset 0 of the EX
            # struct anyway, so the address is the one CreateProcess reads.
            ctypes.byref(startup.StartupInfo),
            ctypes.byref(info),
        ):
            errors.raise_last_error("CreateProcessW")
        try:
            return int(info.dwProcessId)
        finally:
            process.close_handle(info.hProcess or 0)
            process.close_handle(info.hThread or 0)
    finally:
        raw.k32.DeleteProcThreadAttributeList(attribute_list)
