"""Windows implementation of the signing oracle: named pipes, blocking I/O,
and a watchdog thread.

Named pipes are not a stylistic choice: `GetNamedPipeClientProcessId` is the
only way to learn a peer's identity from the kernel on Windows.
"""

from __future__ import annotations

from . import connection, peercred, session

__all__ = ["connection", "peercred", "session"]
