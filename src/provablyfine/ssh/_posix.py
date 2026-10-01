"""The POSIX end of the ssh-agent client.

`ssh.agent` dispatches here (or to `_win32.connect`) by platform. Both the
system ssh-agent and pf's own oracle listen on a UNIX socket whose path is
whatever the caller has; for the system agent that path is in the
environment, which is the only resolution this endpoint must do.
"""

from __future__ import annotations

import os
import socket

from . import wire


def connect(path: str | None) -> wire.Transport:
    if path is None:
        path = os.environ.get("SSH_AUTH_SOCK")
        if path is None:
            raise OSError("SSH_AUTH_SOCK is not set")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path.encode("ascii"))
    return sock
