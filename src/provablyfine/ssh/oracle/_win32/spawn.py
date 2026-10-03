"""Starting the oracle subprocess"""

from __future__ import annotations

import subprocess
import sys

from .... import jwk
from ... import _w32 as w32
from ... import buffer
from . import peercred, server


def oracle_process_security_attributes() -> w32.security.OwnedSecurityAttributes:
    """A process-object DACL that keeps the oracle unreadable from outside.

    The Windows counterpart of `_posix._runner._lock_down()`'s
    `PR_SET_DUMPABLE`/`PT_DENY_ATTACH`: object access is decided by this DACL
    at `OpenProcess` time, and a process HANDLE is never rechecked after it is
    granted, so the descriptor has to be in force from the process object's
    first instant -- which only `CreateProcessW`'s `lpProcessAttributes`
    achieves. Locking down from inside the runner instead would let anything
    that opened a handle before the change keep reading forever.

    The same user keeps `QUERY_LIMITED_INFORMATION|SYNCHRONIZE` (process times,
    wait for exit), which `peercred`-style observation needs; that exposes no
    memory. Administrators get the same limited rights *from the DACL*, on
    purpose: their real power to read anything comes from `SeDebugPrivilege`,
    which no DACL can gate and no claim here pretends to. A DACL that granted
    Administrators full control would even weaken the boundary, because an
    ssh-session/admin token has that group *enabled* without anyone holding
    anything privileged. Deliberately absent for the user: `VM_READ`/
    `VM_WRITE`, `CREATE_THREAD`, `SUSPEND_RESUME`, `TERMINATE`, and `WRITE_DAC`
    (owner rights do not let a non-privileged user re-loosen this later).
    """
    sid = w32.security.current_user_sid()
    readable = w32.raw.PROCESS_QUERY_LIMITED_INFORMATION | w32.raw.SYNCHRONIZE
    sddl = f"O:{sid}G:{sid}D:(A;;GA;;;SY)(A;;0x{readable:x};;;BA)(A;;0x{readable:x};;;{sid})"
    return w32.security.security_attributes(sddl, inheritable=False)


def spawn_subprocess(
    handle: int,
    key: jwk.Private,
    identities: list[server.Identity],
    anchor: peercred.Anchor,
    ttl: float,
    *,
    mode: str,
    event_name: str | None = None,
    logon_sid: str | None = None,
) -> int:
    """Start `_runner.py` in a fresh interpreter and return the child's pid.

    `subprocess.Popen` would do everything except one thing this needs: give
    the child process object a security descriptor. Object access is decided
    when a HANDLE is opened and never revisited, so a process that locks its
    own DACL down after the fact leaves anything that opened it earlier still
    reading. Only `CreateProcessW`'s `lpProcessAttributes` is in force from the
    process object's first instant -- hence `w32.spawn.spawn_detached_process`
    here rather than `Popen`. See `oracle_process_security_attributes` for what
    the descriptor says and why.

    The pipe HANDLE still crosses by inheritance, now through an explicit
    handle list instead of `STARTUPINFO.lpAttributeList`: it names exactly
    what the child receives (the pipe, the stdin read end, the NUL handle),
    which is `close_fds=True`'s job restated. The private key crosses over the
    stdin pipe: POSIX's `pass_fds` does not exist here. It is buffered into
    the pipe before the child starts, so the child never blocks on a parent
    that has forgotten about it, and a failed spawn never leaves a child
    waiting for a key that will not come.

    The caller creates the pipe before calling this, which is the analogue of
    POSIX's bind-before-spawn: it is accept-ready before the caller proceeds,
    so there is no "is the oracle up yet" race, and the name is claimed before
    anything else could take it.
    """
    payload = buffer.Writer()
    payload.write_string(key.to_pem())
    payload.write_uint32(len(identities))
    for identity in identities:
        payload.write_string(identity.raw)

    argv = [
        sys.executable,
        "-m",
        "provablyfine.ssh.oracle._win32._runner",
        mode,
        str(handle),
        peercred.anchor_spawn_token(anchor),
        str(ttl),
        "-" if event_name is None else event_name,
        "-" if logon_sid is None else logon_sid,
    ]
    stdin_read, stdin_write = w32.pipe.create_inheritable_pipe()
    std_null = w32.pipe.open_nul()
    try:
        try:
            w32.pipe.write_file(stdin_write, payload.to_bytes())
        finally:
            w32.process.close_handle(stdin_write)
        return w32.spawn.spawn_detached_process(
            subprocess.list2cmdline(argv),
            inherit=(handle, stdin_read, std_null),
            std_input=stdin_read,
            std_null=std_null,
            process_security=oracle_process_security_attributes(),
        )
    finally:
        w32.process.close_handle(stdin_read)
        w32.process.close_handle(std_null)
