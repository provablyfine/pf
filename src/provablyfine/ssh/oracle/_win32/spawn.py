"""Starting the oracle subprocess"""

from __future__ import annotations

import subprocess
import sys

from .... import jwk
from ... import buffer
from . import _win32api, peercred, server


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
    process object's first instant -- hence `_win32api.spawn_detached_process`
    here rather than `Popen`. See `_win32api.oracle_process_security_attributes`
    for what the descriptor says and why.

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
    stdin_read, stdin_write = _win32api.create_inheritable_pipe()
    std_null = _win32api.open_nul()
    try:
        try:
            _win32api.write_file(stdin_write, payload.to_bytes())
        finally:
            _win32api.close_handle(stdin_write)
        return _win32api.spawn_detached_process(
            subprocess.list2cmdline(argv),
            inherit=(handle, stdin_read, std_null),
            std_input=stdin_read,
            std_null=std_null,
            process_security=_win32api.oracle_process_security_attributes(),
        )
    finally:
        _win32api.close_handle(stdin_read)
        _win32api.close_handle(std_null)
