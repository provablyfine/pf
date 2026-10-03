"""The POSIX end of the ssh-agent client.

`ssh.agent` dispatches here (or to `_win32.connect`) by platform. Both the
system ssh-agent and pf's own oracle listen on a UNIX socket whose path is
whatever the caller has; for the system agent that path is in the
environment, which is the only resolution this endpoint must do.

`check_owner` is for the case where the caller knows the path because pf
derived it, and so can tell an impostor from an absent oracle. The check
itself is `_check_owner` below.
"""

from __future__ import annotations

import os
import socket

from . import exceptions, wire


def connect(path: str | None, *, check_owner: bool = False) -> wire.Transport:
    if path is None:
        path = os.environ.get("SSH_AUTH_SOCK")
        if path is None:
            raise OSError("SSH_AUTH_SOCK is not set")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path.encode("ascii"))
    if check_owner:
        try:
            _check_owner(sock, path)
        except Exception:
            sock.close()
            raise
    return sock


def _check_owner(sock: socket.socket, path: str) -> None:
    # `ssh.oracle` is imported here rather than at module scope:
    # `ssh/__init__.py` imports this module before it, so a top-level import
    # would make that order load-bearing for a call made once per connection.
    from . import oracle

    try:
        peer_uid = oracle.peercred.peer_user_id(sock)
    except (exceptions.Error, OSError) as e:
        raise exceptions.OraclePeerCheckFailed(f"Unable to check who serves {path}: {e}") from e
    our_uid = os.geteuid()
    if peer_uid != our_uid:
        raise exceptions.OraclePeerCheckFailed(
            f"{path} is served by a process running as uid {peer_uid}, not by you (uid {our_uid})."
        )
