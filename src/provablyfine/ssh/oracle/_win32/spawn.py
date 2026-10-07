"""Starting the oracle subprocess"""

from __future__ import annotations

import subprocess
import sys

from .... import _w32 as w32
from .... import jwk
from ... import buffer
from . import peercred, server


def oracle_process_security_attributes() -> w32.security.OwnedSecurityAttributes:
    """A process-object DACL that keeps the oracle unreadable from outside.

    The Windows counterpart of `_posix._runner._lock_down()`'s
    `PR_SET_DUMPABLE`/`PT_DENY_ATTACH`
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
    the child process object a security descriptor.

    The pipe HANDLE still crosses by inheritance, now through an explicit
    handle list instead of `STARTUPINFO.lpAttributeList`: it names exactly
    what the child receives (the pipe, the stdin read end, the NUL handle),
    which is `close_fds=True`'s job restated. The private key crosses over the
    stdin pipe.
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
