"""POSIX implementation of the signing oracle: UNIX sockets, `select()`,
`pass_fds`, and pidfd (Linux) / kqueue + `(pid, start_key)` (Darwin) process
identity.

Linux and Darwin differ only in how "who is this peer, and is that process
still alive" is answered, so they share this transport and split one level
down, in `peercred/`. Windows shares nothing with either and lives in
`.._win32`; see `..__init__` for why.
"""

from __future__ import annotations

from . import connection, peercred, server, session, spawn

__all__ = ["connection", "peercred", "server", "session", "spawn"]
