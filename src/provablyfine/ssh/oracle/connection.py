"""Connection-key oracle: pin to the one specific `ssh` process about to be spawned.

Single-shot, single-factor authorization: the connecting peer must *be* the
anchored process (kernel-verified pidfd identity), not merely a descendant of
it. `_ssh_function` (`cli/pf/ssh_cli.py`) already knows exactly which child it
is about to `execvp()` into -- this pins to that specific, not-yet-existing
process by registering the *current* process's own pidfd as the anchor before
forking (since `execvp` replaces the process image in place, the anchor
process and the eventually-exec'd `ssh` are the same PID/pidfd throughout).

Assumption, stated rather than silently relied on: this assumes the peer
speaking the agent protocol is the exec'd `ssh` process itself, not a child of
it. A `ProxyCommand` or similar configuration that spawns a helper process to
do the actual agent talking would violate that and get rejected. If that turns
out to matter in practice, the fix is reusing `peercred.is_descendant_of()` to
accept descendants of the pinned pidfd too -- not built speculatively here.

`authorize()` below is called from two places: `spawn.spawn_subprocess()`
doesn't call it directly (the oracle now runs as a subprocess, not a fork --
see spawn.py's module docstring -- so there's no shared memory for a Python
closure to survive into); it's reconstructed by `_runner.py` in the spawned
child instead, from the same `anchor_pidfd` passed down as a plain fd number.
"""

from __future__ import annotations

import collections.abc
import os
import socket
import tempfile

from ... import jwk
from .. import exceptions, serde
from . import peercred, server, spawn


def spawn_oracle(key: jwk.Private, cert_blob: bytes, anchor_pidfd: int, ttl: float = 60) -> str:
    """Spawn a connection-key oracle pinned to `anchor_pidfd`.

    Lists both the bare public key and the certificate as separate
    identities, both signed by `key` -- `ssh` invoked with
    `CertificateFile=...` + `IdentitiesOnly=yes` looks the identity up by the
    certificate blob, not the bare key, so both must be present.

    Returns the oracle's socket path -- set it as SSH_AUTH_SOCK for the
    about-to-be-exec'd `ssh` process.
    """
    spawn.require_linux()
    identities = [
        server.Identity(raw=serde.serialize_public(key.public()), key=key),
        server.Identity(raw=cert_blob, key=key),
    ]
    directory = tempfile.mkdtemp(prefix="pf-oracle-")
    path = os.path.join(directory, "s")
    sock = spawn.bind_socket(path)
    spawn.spawn_subprocess(sock, path, key, identities, anchor_pidfd, ttl, mode="connection")
    return path


def authorize(anchor_pidfd: int) -> collections.abc.Callable[[socket.socket], bool]:
    def authorize(conn: socket.socket) -> bool:
        try:
            peer = peercred.peer_identity(conn)
        except (exceptions.Error, OSError):
            return False
        try:
            return peercred.pidfd_same_process(peer.pidfd, anchor_pidfd)
        finally:
            os.close(peer.pidfd)

    return authorize
