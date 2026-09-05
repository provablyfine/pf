"""Kernel-verified peer-process identity for the oracle's UNIX-socket peers.

Pure, server-independent primitives, no socket-protocol knowledge -- just
"who is on the other end of this connection, and is it who we think it is."

Linux only. `SO_PEERCRED`, `os.pidfd_open()`, and `/proc` (all load-bearing
here) are Linux-specific; macOS has no direct equivalent to any of the three
(it would need `LOCAL_PEERCRED` under `SOL_LOCAL` plus an entirely different,
not-yet-designed process-handle primitive). The wider oracle design is
documented as "same conceptual shape, untested" on macOS; this module is
honest that, as implemented, it's simply Linux-only rather than pretending to
be portable. It does not guard against being imported elsewhere (so that
merely importing `provablyfine.ssh` -- which every platform does -- doesn't
crash); the actual platform check lives at the oracle's call-time entry
points (`connection.spawn_oracle`, `session.spawn_oracle`,
`session.current_socket_path`), via `spawn.require_linux()`.

**Residual TOCTOU window, not fully closed**: `SO_PEERPIDFD` (kernel 6.5+,
returns the peer's pidfd directly from `accept()`, closing this window
entirely) is not implemented -- CPython's socket module has no support for a
getsockopt() that returns a file descriptor rather than a byte buffer, and
reaching for ctypes/SCM_RIGHTS tricks was judged not worth the complexity for
a race this small. Instead, `peer_identity()` reads the peer's PID via
`SO_PEERCRED` and immediately calls `os.pidfd_open(pid)` on it. Between those
two kernel calls, that PID could in principle have exited and been recycled
by an unrelated process, which `pidfd_open` would then happily pin instead.
This is a few kernel instructions wide, far tighter than "no pidfd
verification at all" (where the equivalent window is the full lifetime of
other processes on the system), but it is not zero.
"""

from __future__ import annotations

import dataclasses
import os
import select
import socket
import struct

from .. import exceptions

_AUDIT_SESSION_UNSET = 0xFFFFFFFF


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    pid: int
    pidfd: int


def peer_identity(conn: socket.socket) -> PeerIdentity:
    """Kernel-verified (pid, pidfd) for the process on the other end of `conn`.

    Should be called as soon as possible after accept() -- see the TOCTOU
    note in the module docstring. Callers own the returned pidfd and must
    close it once done.
    """
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, _uid, _gid = struct.unpack("3i", raw)
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError as e:
        raise exceptions.Error(f"Peer process {pid} exited before its identity could be verified") from e
    return PeerIdentity(pid=pid, pidfd=pidfd)


def pidfd_file_identity(pidfd: int) -> tuple[int, int]:
    """A pidfd's own (st_dev, st_ino) -- a stable, comparable process identity.

    Two pidfds referencing the same process compare equal here even when
    obtained independently (e.g. one pinned at registration time, another
    from a later peer_identity() call) -- this is about the *process*, not
    the fd number.
    """
    st = os.fstat(pidfd)
    return (st.st_dev, st.st_ino)


def pidfd_same_process(a: int, b: int) -> bool:
    return pidfd_file_identity(a) == pidfd_file_identity(b)


def pidfd_is_alive(pidfd: int) -> bool:
    """True while the referenced process is still running.

    A pidfd becomes readable (POLLIN) the instant its process exits -- this
    is what lets the oracle's accept loop wait on both a TTL deadline and
    "has my anchor process died" without polling.
    """
    readable, _, _ = select.select([pidfd], [], [], 0)
    return len(readable) == 0


def _proc_stat_fields(pid: int) -> list[bytes]:
    # Field 2 (comm) is parenthesized and may itself contain spaces or
    # parens; the *last* ')' in the line unambiguously ends it (the same
    # convention procps-family parsers use), so split from there rather than
    # relying on whitespace splitting of the whole line.
    with open(f"/proc/{pid}/stat", "rb") as f:
        data = f.read()
    rest = data[data.rindex(b")") + 2 :]
    return rest.split()


def process_starttime(pid: int) -> int:
    """Field 22 of /proc/<pid>/stat -- process start time in kernel jiffies.

    Combined with the PID, this is a stable, kernel-issued identity for one
    specific process instance: the same PID reused by a later process gets a
    different starttime.
    """
    return int(_proc_stat_fields(pid)[19])


def controlling_tty_dev(pid: int) -> int | None:
    """Kernel-recorded controlling TTY device number for `pid`, or None if it
    has no controlling terminal (field 7 of /proc/<pid>/stat, 0 = none)."""
    tty_nr = int(_proc_stat_fields(pid)[4])
    return tty_nr if tty_nr != 0 else None


def audit_session_id(pid: int) -> int | None:
    """Linux audit-subsystem session id for `pid` (/proc/<pid>/sessionid).

    Set once, atomically, by PAM (`pam_loginuid`) at login and inherited by
    every descendant process thereafter -- a kernel-tracked, unforgeable
    per-login-session identifier that needs no systemd/logind dependency.
    Returns None when unset (the sentinel value 0xFFFFFFFF), which is the
    normal state outside of a PAM-managed login (e.g. under a test harness
    or a bare `su`/container shell).
    """
    try:
        with open(f"/proc/{pid}/sessionid", "rb") as f:
            value = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None
    if value == _AUDIT_SESSION_UNSET:
        return None
    return value


def read_ppid(pid: int) -> int | None:
    """Parent PID of `pid`, or None if the process is already gone -- a
    normal race at the leaf of an ancestry walk, not an error."""
    try:
        with open(f"/proc/{pid}/status", "rb") as f:
            for line in f:
                if line.startswith(b"PPid:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        return None
    raise exceptions.Error(f"/proc/{pid}/status has no PPid field")


def is_descendant_of(pid: int, anchor_pidfd: int, *, max_depth: int = 64) -> bool:
    """Walk `pid`'s ancestors looking for the process pinned by `anchor_pidfd`.

    Each ancestor's pidfd is opened the instant its PID is read from its
    child's /proc/<pid>/status -- before anything else happens with that PID
    -- so a PID recycled between "we read PPid" and "we act on it" cannot be
    substituted in underneath us. Returns True the moment a hop's pidfd
    identity matches the anchor; False if the walk reaches the process tree
    root, loses the trail (a process exits mid-walk), or exceeds max_depth.

    Does not check `pid` itself against the anchor -- callers that want
    "anchor or a descendant of it" should check pidfd_same_process()
    separately first.
    """
    current = pid
    for _ in range(max_depth):
        ppid = read_ppid(current)
        if ppid is None or ppid == 0:
            return False
        try:
            candidate_pidfd = os.pidfd_open(ppid)
        except ProcessLookupError:
            return False
        try:
            if pidfd_same_process(candidate_pidfd, anchor_pidfd):
                return True
        finally:
            os.close(candidate_pidfd)
        current = ppid
    return False
