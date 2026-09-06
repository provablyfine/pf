"""Peer-credential-gated signing oracle: the single platform dispatch point.

`_posix` and `_win32` are two *independent* implementations, deliberately
sharing no code with each other. They can't reasonably be unified: `_posix`
is built on UNIX sockets, `select()`, `pass_fds` and pidfd/kqueue process
handles; `_win32` is built on named pipes, overlapped I/O,
`WaitForMultipleObjects` and Win32 process HANDLEs.

Within `_posix`, a second, narrower dispatch picks the Linux or Darwin
peercred backend (see `_posix/peercred/__init__.py`) -- those two are close
enough to be siblings under one transport, which is why they live together
and `_win32` does not.
"""

from __future__ import annotations

import sys

if sys.platform == "win32":
    from ._win32 import connection, peercred, session
else:
    from ._posix import connection, peercred, session

__all__ = ["connection", "peercred", "session"]
