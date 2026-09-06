"""Peer-credential-gated signing oracle: the single platform dispatch point.

`_posix` and `_win32` are two *independent* implementations, deliberately
sharing no code with each other. They can't reasonably be unified: `_posix`
is built on UNIX sockets, `select()`, `pass_fds` and pidfd/kqueue process
handles; `_win32` is built on named pipes, overlapped I/O,
`WaitForMultipleObjects` and Win32 process HANDLEs. What they share is the
*interface* below -- callers reach `connection`, `session`, `peercred` etc.
through this module and never name a platform themselves.

Within `_posix`, a second, narrower dispatch picks the Linux or Darwin
peercred backend (see `_posix/peercred/__init__.py`) -- those two are close
enough to be siblings under one transport, which is why they live together
and `_win32` does not.
"""

from __future__ import annotations

import sys

if sys.platform == "win32":
    from ._win32 import connection, peercred, server, session, spawn
else:
    from ._posix import connection, peercred, server, session, spawn

__all__ = ["connection", "peercred", "server", "session", "spawn"]
