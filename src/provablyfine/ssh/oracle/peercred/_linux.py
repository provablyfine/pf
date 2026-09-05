"""Kernel-verified peer-process identity for the oracle's UNIX-socket peers,
on Linux.

`SO_PEERCRED`, `os.pidfd_open()`, and `/proc` (all load-bearing here) are
Linux-specific -- see `_darwin.py` for the equivalent primitives there.
"""

from __future__ import annotations

import dataclasses
import os
import socket
import struct

from ... import exceptions

_AUDIT_SESSION_UNSET = 0xFFFFFFFF


@dataclasses.dataclass(frozen=True)
class Anchor:
    """A pinned, kernel-verified process instance, watchable for exit.

    `fd` is a pidfd: select()-able (readable the instant the process exits)
    and comparable via `os.fstat()` (two pidfds referencing the same process
    compare equal on `(st_dev, st_ino)` even when opened independently).
    """

    fd: int


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    pid: int
    pidfd: int


def peer_identity(conn: socket.socket) -> PeerIdentity:
    """Kernel-verified (pid, pidfd) for the process on the other end of `conn`.

    Ideally, we would use SO_PEERPIDFD (kernel 6.5+) to close the TOCTOU
    window that opens after SO_PEERCRED returns and before pidfd_open is called.
    """
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, _uid, _gid = struct.unpack("3i", raw)
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError as e:
        raise exceptions.Error(f"Peer process {pid} exited before its identity could be verified") from e
    return PeerIdentity(pid=pid, pidfd=pidfd)


def close_peer_identity(peer: PeerIdentity) -> None:
    os.close(peer.pidfd)


def _pidfd_file_identity(pidfd: int) -> tuple[int, int]:
    """A pidfd's own (st_dev, st_ino) -- a stable, comparable process identity.

    Two pidfds referencing the same process compare equal here even when
    obtained independently (e.g. one pinned at registration time, another
    from a later peer_identity() call) -- this is about the *process*, not
    the fd number.
    """
    st = os.fstat(pidfd)
    return (st.st_dev, st.st_ino)


def same_process(peer: PeerIdentity, anchor: Anchor) -> bool:
    return _pidfd_file_identity(peer.pidfd) == _pidfd_file_identity(anchor.fd)


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


def peer_session_facts(_conn: socket.socket, peer: PeerIdentity) -> tuple[int | None, int | None]:
    """(audit session id, controlling tty device) for `peer`, or None each
    when unavailable.

    Re-reads /proc/<peer.pid>/{sessionid,stat} by raw PID rather than through
    the already-pinned peer.pidfd -- there is no pidfd-scoped way to read
    these two facts. Same class of tight TOCTOU window as peer_identity()'s
    own SO_PEERCRED->pidfd_open gap above: the peer would have to exit and
    have its PID reassigned to a new process within the few Python bytecode
    instructions between here and the caller's ancestry check. Not closed to
    zero, judged acceptable.
    """
    return audit_session_id(peer.pid), controlling_tty_dev(peer.pid)


def parent_session_id(pid: int) -> int | None:
    """`audit_session_id(pid)` under the name `session.py` calls at
    spawn/pin time -- distinct from `peer_session_facts()` only in when it
    runs (before any connection exists) and what it's about (the anchor
    itself, not a connecting peer)."""
    return audit_session_id(pid)


def parent_tty_dev(pid: int) -> int | None:
    return controlling_tty_dev(pid)


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


def is_descendant_of(pid: int, anchor: Anchor, *, max_depth: int = 64) -> bool:
    """Walk `pid`'s ancestors looking for the process pinned by `anchor`.

    Each ancestor's pidfd is opened the instant its PID is read from its
    child's /proc/<pid>/status -- before anything else happens with that PID
    -- so a PID recycled between "we read PPid" and "we act on it" cannot be
    substituted in underneath us. Returns True the moment a hop's pidfd
    identity matches the anchor; False if the walk reaches the process tree
    root, loses the trail (a process exits mid-walk), or exceeds max_depth.

    Does not check `pid` itself against the anchor -- callers that want
    "anchor or a descendant of it" should check same_process() separately
    first.
    """
    anchor_identity = _pidfd_file_identity(anchor.fd)
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
            if _pidfd_file_identity(candidate_pidfd) == anchor_identity:
                return True
        finally:
            os.close(candidate_pidfd)
        current = ppid
    return False


def open_anchor(pid: int) -> Anchor:
    return Anchor(fd=os.pidfd_open(pid))


def close_anchor(anchor: Anchor) -> None:
    os.close(anchor.fd)


def anchor_extra_fds(anchor: Anchor) -> tuple[int, ...]:
    """A *duplicate* of this anchor's pidfd, to ride along via `pass_fds`
    into a spawned oracle subprocess -- see spawn.py.

    Deliberately a dup, not `anchor.fd` itself: spawn.py owns closing
    whatever `anchor_extra_fds()` hands back (its own copy, handed to the
    child) independently of `close_anchor()` (which releases the Anchor's
    own fd) -- sharing one fd number between both closers would double-close
    it in the common case where `_dup_above_stdio` doesn't need to relocate
    anything.
    """
    return (os.dup(anchor.fd),)


def anchor_spawn_token(_anchor: Anchor, extra_fds: tuple[int, ...]) -> str:
    """argv token encoding `anchor`, given `extra_fds` -- the *final*,
    already pass_fds-safe fd numbers corresponding 1:1 to
    `anchor_extra_fds(anchor)` -- since a pidfd's fd number is itself the
    entire identity that needs to cross the process boundary."""
    (fd,) = extra_fds
    return f"fd:{fd}"


def reconstruct_anchor(token: str) -> Anchor:
    """Rebuild the `Anchor` a spawning process encoded with
    `anchor_spawn_token()`, from inside the spawned child -- see
    _runner.py. The fd number in `token` is already valid in this process:
    `pass_fds` preserves fd numbers as-is across fork+exec."""
    kind, value = token.split(":", 1)
    assert kind == "fd", f"unexpected anchor token kind on Linux: {kind!r}"
    return Anchor(fd=int(value))
