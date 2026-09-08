"""Oracle subprocess entry point -- `python -m provablyfine.ssh.oracle._win32._runner`.

Never invoked directly; `session._spawn_subprocess()` starts it. Everything the
oracle needs crosses via an inherited HANDLE, argv, and stdin, since this is a
fresh interpreter rather than a forked copy of the spawning process's memory:
there is no shared memory for a Python object to arrive through.

argv: mode pipe_handle anchor_token ttl new_login_event_name logon_sid
  - mode: "connection" or "session" -- which of connection.authorize /
    session.authorize to reconstruct and run.
  - pipe_handle: the listening pipe, already created and inheritable in the
    parent, so its numeric value is valid here unchanged.
  - anchor_token: `pidstart:<pid>:<creation_time>`, read by
    `peercred.reconstruct_anchor()`.
  - ttl: seconds.
  - new_login_event_name, logon_sid: "-" for None. Both are always "-" for
    mode "connection".

The private key and identity blobs arrive on stdin: one `buffer.Writer` payload
of string(key PEM) + uint32(count) + that many string(raw identity blob), all
signed by the same key, written by the parent which then closed the pipe.

Nothing is cleaned up on exit and nothing needs to be: a named pipe ceases to
exist when its server process does, and `server.serve()` never returns anyway
"""

from __future__ import annotations

import sys

from .... import jwk, log
from ... import buffer
from . import _win32api, connection, peercred, server, session


def _read_key_material() -> tuple[jwk.Private, list[bytes]]:
    data = sys.stdin.buffer.read()
    reader = buffer.Reader(data)
    key = jwk.Private.from_pem(reader.read_string())
    identity_count = reader.read_uint32()
    return key, [reader.read_string() for _ in range(identity_count)]


def main() -> None:
    # Before anything that can fail. `.._posix._runner` configures no logging
    # at all, which is survivable on Linux where you can rerun it by hand; this
    # process is detached, console-less, and has stderr on DEVNULL, so without
    # this a crash would leave nothing behind at all. Level 0 stays silent
    # unless PF_LOG_LEVEL says otherwise, and PF_LOG_DIRECTORY picks the file.
    log.setup_server("oracle", 0)

    mode = sys.argv[1]
    pipe_handle = int(sys.argv[2])
    anchor_token = sys.argv[3]
    ttl = float(sys.argv[4])
    new_login_event_name = None if sys.argv[5] == "-" else sys.argv[5]
    logon_sid = None if sys.argv[6] == "-" else sys.argv[6]

    key, raws = _read_key_material()
    identities = [server.Identity(raw=raw, key=key) for raw in raws]
    anchor = peercred.reconstruct_anchor(anchor_token)

    if mode == "connection":
        authorize = connection.authorize(anchor)
    elif mode == "session":
        authorize = session.authorize(anchor, logon_sid)
    else:
        raise ValueError(f"unknown oracle mode: {mode}")

    new_login_event = None
    if new_login_event_name is not None:
        new_login_event = _win32api.create_event(new_login_event_name)
        # CreateEventW on an existing name *opens* that event rather thani
        # creating one. A predecessor we just displaced may still be
        # referenced (by the spawning parent's handle) and is signaled,
        # so without this reset our own watchdog would fire immediately.
        _win32api.reset_event(new_login_event)

    server.serve(
        pipe_handle,
        authorize,
        identities,
        ttl=ttl,
        anchor=anchor,
        new_login_event=new_login_event,
    )


if __name__ == "__main__":
    main()
