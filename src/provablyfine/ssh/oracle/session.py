"""Session-key oracle: bind to the login shell's ancestry (run0-style), not to
one known process -- there isn't one, since the legitimate callers are
separate, not-yet-existing future `pf`/`pfa` invocations over the key's whole
TTL (~1800s).

At `pf login` time (`browser_login.generate_session_key()`), three
kernel-verified facts about the *parent* process (the login shell) are
recorded:
  1. A pidfd pinned to the parent process itself -- the mandatory, always-
     active factor. Every later caller must be that exact process or a
     kernel-verified descendant of it (ancestry-walked, not raw PID
     comparison).
  2. The parent's Linux audit-subsystem session id, when set.
  3. The parent's controlling TTY device number, when it has one.

Factors 2 and 3 are *omitted*, not treated as always-matching, when
unavailable -- e.g. under a test harness, CI runner, or `su`/container shell
with no PAM-assigned session and no controlling terminal, this degrades to
factor 1 alone. The design this module implements went through the same
question in public elsewhere: systemd's `run0` (a `sudo` replacement) and its
underlying `polkit` authorization framework converged on binding to session +
parent process + TTY (all three, pidfd-verified) rather than session-wide
trust, and a Windows analysis of the same problem for `pf` found no
TTY-equivalent there at all and still shipped 2-factor rather than refusing
to run -- this module's degrade-not-refuse behavior follows that same
precedent.

**Real tradeoff, accepted deliberately**: when factors 2/3 *are* available,
this ties the session key to the specific terminal `pf login` ran in for the
whole TTL. A second terminal opened mid-session fails the parent-process/TTY
check and needs its own `pf login` -- a real UX change from "signed once,
usable from anywhere in the session," and the same tradeoff sudo's default
and systemd's `run0` make on purpose, for the same reason.

The socket path is derived from the parent process's PID and start time
(not from the session id or TTY, which can both legitimately be absent) --
this is addressing only, not a security boundary: a guessed or colliding path
buys an attacker nothing without also passing the ancestry walk at accept().
Any later invocation in the same shell recomputes the same path with no
config write; a different shell recomputes a different path and correctly
finds nothing listening.
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
    material = f"{parent_pid}:{parent_starttime}".encode()
    digest = hashlib.sha256(material).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), f"pf-session-oracle-{digest}", "s")


def current_socket_path() -> str:
    """Recompute this invocation's session-oracle path from its own parent.

    Used by later `pf`/`pfa` invocations in the same shell to find the
    oracle `pf login` spawned there.
    """
    spawn.require_linux()
    parent_pid = os.getppid()
    parent_starttime = peercred.process_starttime(parent_pid)
    return socket_path(parent_pid, parent_starttime)


def spawn_oracle(key: jwk.Private, ttl: float = 1800) -> str:
    """Spawn a session-key oracle bound to the calling process's parent ancestry.

    Returns the oracle's socket path.
    """
    spawn.require_linux()
    parent_pid = os.getppid()
    parent_pidfd = os.pidfd_open(parent_pid)
    parent_starttime = peercred.process_starttime(parent_pid)
    session_id = peercred.audit_session_id(parent_pid)
    tty_dev = peercred.controlling_tty_dev(parent_pid)

    path = socket_path(parent_pid, parent_starttime)
    sock = spawn.bind_socket(path, replace=True)
    identities = [server.Identity(raw=serde.serialize_public(key.public()), key=key)]
    spawn.spawn_subprocess(
        sock, path, key, identities, parent_pidfd, ttl, mode="session", session_id=session_id, tty_dev=tty_dev
    )
    return path


def authorize(
    parent_pidfd: int, session_id: int | None, tty_dev: int | None
) -> collections.abc.Callable[[socket.socket], bool]:
    # Reconstructed by _runner.py in the spawned oracle subprocess, from the
    # same primitives passed down via pass_fds/argv -- not called directly by
    # spawn_oracle() above, since the oracle runs as a subprocess (see
    # spawn.py's module docstring), not a fork, so there's no shared memory
    # for a Python closure built here to survive into.
    def authorize(conn: socket.socket) -> bool:
        try:
            peer = peercred.peer_identity(conn)
        except (exceptions.Error, OSError):
            return False
        try:
            if not (
                peercred.pidfd_same_process(peer.pidfd, parent_pidfd)
                or peercred.is_descendant_of(peer.pid, parent_pidfd)
            ):
                return False
            # Re-reads /proc/<peer.pid>/{sessionid,stat} by raw PID rather than
            # through the already-pinned peer.pidfd -- there is no pidfd-scoped
            # way to read these two facts. Same class of tight TOCTOU window as
            # peer_identity()'s own SO_PEERCRED->pidfd_open gap (see peercred.py):
            # the peer would have to exit and have its PID reassigned to a new
            # process within the few Python bytecode instructions between here
            # and the ancestry check above. Not closed to zero, judged acceptable
            # for the same reason that gap is.
            if session_id is not None and peercred.audit_session_id(peer.pid) != session_id:
                return False
            if tty_dev is not None and peercred.controlling_tty_dev(peer.pid) != tty_dev:
                return False
            return True
        finally:
            os.close(peer.pidfd)

    return authorize
