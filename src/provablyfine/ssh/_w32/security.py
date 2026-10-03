"""Tokens, SIDs, and security descriptors.

The mechanics only: read a user or logon SID off a process token, turn an SDDL
string into a `SECURITY_ATTRIBUTES`, remove a privilege. The *policies* -- which
DACL to apply to the oracle's process object -- live with their callers.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import dataclasses

from .. import exceptions
from . import errors, process, raw


@dataclasses.dataclass(frozen=True)
class OwnedSecurityAttributes:
    """A `SECURITY_ATTRIBUTES` bundled with the descriptor it points at.

    `lpSecurityDescriptor` is a bare pointer into a `LocalAlloc`'d block. With
    nothing holding a Python reference to that block it would be collected
    while the kernel still had the pointer, so the two have to travel together.
    Callers pass `.attributes` and keep the holder alive across the call.
    """

    attributes: raw.SECURITY_ATTRIBUTES
    descriptor: ctypes.wintypes.LPVOID = dataclasses.field(repr=False)


def token_sid_string(process_token: int, token_class: int, sid_offset: int, buffer_size: int) -> str:
    """Read the SID from a single-SID token class and render it as a string.

    Both `TokenUser` and `TokenLogonSid` return a single `SID_AND_ATTRIBUTES`
    (at the head of the token's structure), so a buffer of `buffer_size` bytes
    and the byte offset of the `Sid` pointer inside it cover both. The offset
    differs: `TOKEN_USER`'s SID is at 0, while `TOKEN_GROUPS`'s sits after the
    leading `GroupCount` DWORD.
    """
    size = ctypes.wintypes.DWORD()
    # The sizing call is *expected* to fail with ERROR_INSUFFICIENT_BUFFER and
    # fill `size`; that is how the required length is learned.
    raw.adv.GetTokenInformation(process_token, token_class, None, 0, ctypes.byref(size))
    # The SID lives *inside* this buffer, so it has to stay alive across the
    # ConvertSidToStringSidW call below.
    buffer = ctypes.create_string_buffer(max(size.value, buffer_size))
    if not raw.adv.GetTokenInformation(process_token, token_class, buffer, len(buffer), ctypes.byref(size)):
        errors.raise_last_error("GetTokenInformation")
    sid = ctypes.cast(ctypes.byref(buffer, sid_offset), ctypes.POINTER(ctypes.wintypes.LPVOID)).contents
    string_sid = ctypes.wintypes.LPWSTR()
    if not raw.adv.ConvertSidToStringSidW(sid, ctypes.byref(string_sid)):
        errors.raise_last_error("ConvertSidToStringSidW")
    try:
        return string_sid.value or ""
    finally:
        raw.k32.LocalFree(ctypes.cast(string_sid, ctypes.wintypes.HLOCAL))


def current_user_sid() -> str:
    """This process's user SID, rendered for use in a security descriptor."""
    process_token = ctypes.wintypes.HANDLE()
    if not raw.adv.OpenProcessToken(raw.k32.GetCurrentProcess(), raw.TOKEN_QUERY, ctypes.byref(process_token)):
        errors.raise_last_error("OpenProcessToken")
    try:
        return token_sid_string(process_token.value or 0, raw.TOKEN_USER_CLASS, 0, ctypes.sizeof(raw.TOKEN_USER))
    finally:
        process.close_handle(process_token.value or 0)


def process_user_sid(process_handle: int) -> str:
    """The user SID of the process `process_handle` refers to.

    Raises on a read failure. Its caller is a security check that has to answer
    "is this ours", and "could not tell" is not an answer that lets the check
    pass. `logon_sid` can afford None because it is one optional factor of a
    two-factor test.
    """
    process_token = ctypes.wintypes.HANDLE()
    if not raw.adv.OpenProcessToken(process_handle, raw.TOKEN_QUERY, ctypes.byref(process_token)):
        errors.raise_last_error("OpenProcessToken")
    try:
        return token_sid_string(process_token.value or 0, raw.TOKEN_USER_CLASS, 0, ctypes.sizeof(raw.TOKEN_USER))
    finally:
        process.close_handle(process_token.value or 0)


def logon_sid(process_handle: int) -> str | None:
    """The logon SID of `process_handle`, or None if it cannot be read.

    Returns None rather than raising so callers can decide how to degrade: the
    anchor's SID is optional (fall back to anchor-only binding), while a peer's
    SID failing to read is a rejection. `OpenProcessToken` accepts the same
    `PROCESS_QUERY_LIMITED_INFORMATION` handle `process.open_process` returns.
    """
    process_token = ctypes.wintypes.HANDLE()
    if not raw.adv.OpenProcessToken(process_handle, raw.TOKEN_QUERY, ctypes.byref(process_token)):
        return None
    try:
        return token_sid_string(
            process_token.value or 0,
            raw.TOKEN_LOGON_SID_CLASS,
            # The Groups array is aligned to its own element alignment, so its
            # offset is GroupCount's size rounded up to that alignment. This
            # avoids `ctypes.offsetof`, which typeshed does not declare.
            (ctypes.sizeof(ctypes.wintypes.DWORD) + ctypes.alignment(raw.SID_AND_ATTRIBUTES) - 1)
            // ctypes.alignment(raw.SID_AND_ATTRIBUTES)
            * ctypes.alignment(raw.SID_AND_ATTRIBUTES),
            ctypes.sizeof(raw.TOKEN_GROUPS),
        )
    except exceptions.Error:
        return None
    finally:
        process.close_handle(process_token.value or 0)


def security_attributes(sddl: str, *, inheritable: bool) -> OwnedSecurityAttributes:
    descriptor = ctypes.wintypes.LPVOID()
    if not raw.adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, raw.SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        errors.raise_last_error("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    attributes = raw.SECURITY_ATTRIBUTES()
    attributes.nLength = ctypes.sizeof(raw.SECURITY_ATTRIBUTES)
    attributes.lpSecurityDescriptor = descriptor
    attributes.bInheritHandle = inheritable
    return OwnedSecurityAttributes(attributes=attributes, descriptor=descriptor)


def owner_only_security_attributes(*, inheritable: bool) -> OwnedSecurityAttributes:
    """Security attributes granting full access to this user and SYSTEM only.

    A UNIX socket inherits the protection of the directory holding it, which is
    what the POSIX oracle's spawn relies on with its 0700 directory.
    `\\\\.\\pipe\\` is a flat, machine-global namespace with no directory to hide
    behind, so the restriction has to be stated on the object itself.

    Like its POSIX counterpart this is belt-and-braces: the real boundary is
    the peer-credential check at accept().
    """
    sid = current_user_sid()
    return security_attributes(f"O:{sid}G:{sid}D:(A;;GA;;;{sid})(A;;GA;;;SY)", inheritable=inheritable)


def disable_debug_privilege() -> None:
    """Take `SeDebugPrivilege` away from this process, best effort.

    `OpenProcess` grants access through that privilege *before* consulting any
    DACL, so a test of a process DACL only measures the DACL if the holder has
    first disarmed it. What is left after this is precisely the ordinary
    same-user attacker a DACL exists to stop. Processes that do not hold the
    privilege keep failing to use it, which is also fine."""
    luid = raw.LUID()
    if not raw.adv.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        return
    token = ctypes.wintypes.HANDLE()
    if not raw.adv.OpenProcessToken(
        raw.k32.GetCurrentProcess(), raw.TOKEN_ADJUST_PRIVILEGES | raw.TOKEN_QUERY, ctypes.byref(token)
    ):
        return
    try:
        state = raw.TOKEN_PRIVILEGES(1, (raw.LUID_AND_ATTRIBUTES(luid, 0),))
        raw.adv.AdjustTokenPrivileges(token, False, ctypes.byref(state), 0, None, None)
    finally:
        process.close_handle(token.value or 0)
