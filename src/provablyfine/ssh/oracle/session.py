"""Session-key oracle: bind to the login shell's ancestry (run0-style), not to
one known process -- there isn't one, since the legitimate callers are
separate, not-yet-existing future `pf`/`pfa` invocations over the key's whole
TTL (~1800s).

At `pf login` time (`browser_login.generate_session_key()`), three
kernel-verified facts about the *parent* process (the login shell) are
recorded:
  1. An anchor pinned to the parent process itself -- the mandatory,
     always-active factor. Every later caller must be that exact process or
     a kernel-verified descendant of it (ancestry-walked, not raw PID
     comparison). See `peercred` for what "anchor" means per platform (a
     pidfd on Linux; a verified `(pid, start_key)` plus a kqueue exit-watch
     on Darwin).
  2. The parent's audit-subsystem session id, when set (Linux: read
     directly for the parent pid off `/proc/<pid>/sessionid`; Darwin: the
     *current* process's own, via `getaudit_addr()`, relying on BSM asid
     inheritance across fork -- see `peercred._darwin.parent_session_id()`
     for why an arbitrary pid's asid can't be read directly there).
  3. The parent's controlling TTY device number, when it has one.

Factors 2 and 3 are *omitted*, not treated as always-matching, when
unavailable. e.g. under a test harness, CI runner, or `su`/container shell
with no PAM-assigned session and no controlling terminal, this degrades to
factor 1 alone.

The design this module implements was inspired by the approach discussed in public
elsewhere: systemd's `run0` (a `sudo` replacement) and its underlying `polkit`
authorization framework converged on binding to session + parent process + TTY
(all three, kernel-verified) rather than session-wide trust.

This trust model should be compared to the ssh-agent model where trust
is given to processes who are able to read and write the user's agent unix
socket. i.e., any process owned by this user.

"""

from __future__ import annotations

import collections.abc
import hashlib
import os
import socket
import tempfile

from ... import jwk
from .. import exceptions, serde
from . import peercred, server, spawn


def socket_path(parent_pid: int, parent_starttime: int) -> str:
    """The socket path is derived from the parent process's PID and start time.

    The requirement is merely to be deterministic. no security issue here since
    any user would need to pass the access control check implemented in the oracle
    """

    material = f"{parent_pid}:{parent_starttime}".encode()
    digest = hashlib.sha256(material).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), f"pf-session-oracle-{digest}", "s")


def current_socket_path() -> str:
    """Recompute this invocation's session-oracle path from its own parent.

    Used by later `pf`/`pfa` invocations in the same shell to find the
    oracle `pf login` spawned there.
    """
    spawn.require_platform_supported()
    parent_pid = os.getppid()
    parent_starttime = peercred.process_starttime(parent_pid)
    return socket_path(parent_pid, parent_starttime)


def spawn_oracle(key: jwk.Private, ttl: float = 1800) -> str:
    """Spawn a session-key oracle bound to the calling process's parent ancestry.

    Returns the oracle's socket path.
    """
    spawn.require_platform_supported()
    parent_pid = os.getppid()
    parent_anchor = peercred.open_anchor(parent_pid)
    parent_starttime = peercred.process_starttime(parent_pid)
    session_id = peercred.parent_session_id(parent_pid)
    tty_dev = peercred.parent_tty_dev(parent_pid)

    path = socket_path(parent_pid, parent_starttime)
    sock = spawn.bind_socket(path, replace=True)
    identities = [server.Identity(raw=serde.serialize_public(key.public()), key=key)]
    spawn.spawn_subprocess(
        sock, path, key, identities, parent_anchor, ttl, mode="session", session_id=session_id, tty_dev=tty_dev
    )
    return path


def authorize(
    anchor: peercred.Anchor, session_id: int | None, tty_dev: int | None
) -> collections.abc.Callable[[socket.socket], bool]:
    # Reconstructed by _runner.py in the spawned oracle subprocess, from the
    # same anchor passed down via pass_fds/argv -- not called directly by
    # spawn_oracle() above, since the oracle runs as a subprocess (see
    # spawn.py's module docstring), not a fork, so there's no shared memory
    # for a Python closure built here to survive into.
    def authorize(conn: socket.socket) -> bool:
        try:
            peer = peercred.peer_identity(conn)
        except (exceptions.Error, OSError):
            return False
        try:
            if not (peercred.same_process(peer, anchor) or peercred.is_descendant_of(peer.pid, anchor)):
                return False
            peer_session_id, peer_tty_dev = peercred.peer_session_facts(conn, peer)
            if session_id is not None and peer_session_id != session_id:
                return False
            if tty_dev is not None and peer_tty_dev != tty_dev:
                return False
            return True
        finally:
            peercred.close_peer_identity(peer)

    return authorize
