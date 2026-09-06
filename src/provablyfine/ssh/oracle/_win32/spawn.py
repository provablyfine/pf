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
    session_id: int | None = None,
) -> None:
    """Start `_runner.py` in a fresh interpreter and return immediately.

    The pipe HANDLE crosses by inheritance (`handle_list`), which preserves its
    numeric value in the child, so argv can just name it. The private key
    crosses over stdin: POSIX's `pass_fds` does not exist here.

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

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.lpAttributeList = {"handle_list": [handle]}
    argv = [
        sys.executable,
        "-m",
        "provablyfine.ssh.oracle._win32._runner",
        mode,
        str(handle),
        peercred.anchor_spawn_token(anchor),
        str(ttl),
        "-" if event_name is None else event_name,
        "-" if session_id is None else str(session_id),
    ]
    child = subprocess.Popen(  # noqa: S603
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        startupinfo=startupinfo,
        # The analogue of POSIX `start_new_session=True`, and it matters more
        # here: Windows broadcasts console control events to every process
        # attached to the console, so without detaching, a Ctrl+C in the shell
        # would take the oracle down with the CLI.
        creationflags=_win32api.DETACHED_PROCESS | _win32api.CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )
    assert child.stdin is not None
    try:
        child.stdin.write(payload.to_bytes())
    finally:
        child.stdin.close()
