"""Kernel-verified peer-process identity for the oracle's UNIX-socket peers,
on macOS.

Neither of Linux's load-bearing primitives exists here (see `_linux.py`'s
module docstring), but macOS has its own kernel-verified equivalents for
every fact this package needs:

- `LOCAL_PEERTOKEN` under `SOL_LOCAL` (`<sys/un.h>`) returns the connecting
  peer's Mach audit token in one `getsockopt()` call -- both its real pid
  (`audit_token_to_pid()`) and its BSM audit session id
  (`audit_token_to_asid()`), from `libbsm`. This is actually *tighter* than
  Linux here: the asid arrives attributed by the kernel on the socket
  itself, with no equivalent of `_linux.py`'s "re-read /proc/<pid>/sessionid
  by raw pid" TOCTOU gap.
- `libproc`'s `proc_pidinfo(PROC_PIDTBSDINFO)` (`<libproc.h>`,
  `<sys/proc_info.h>`) gives a process's parent pid, controlling-tty device,
  and start time in one call -- the equivalents of `/proc/<pid>/status`'s
  PPid, `/proc/<pid>/stat` fields 7 and 22.
- `kqueue`'s `EVFILT_PROC`/`NOTE_EXIT` gives a select()-able fd that becomes
  readable the instant a pinned pid exits -- the equivalent of a Linux
  pidfd's poll behavior (verified empirically: level-triggered while the
  exit event sits undrained in the queue, exactly like a pidfd). Unlike a
  pidfd, though, it is *not* a comparable process identity by itself and
  does *not* survive fork/exec (verified empirically: a kqueue fd inherited
  via `pass_fds` is dead -- `EBADF` -- in the child). So an `Anchor` here
  pairs the watch fd with a separately-verified `(pid, start_key)` identity,
  and a spawned oracle subprocess re-registers its own watch from scratch
  (see `reconstruct_anchor()`) rather than inheriting one.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import dataclasses
import os
import select
import socket
import struct

from .... import exceptions
from . import _linux

_SOL_LOCAL = 0
_LOCAL_PEERTOKEN = 0x006
_PROC_PIDTBSDINFO = 3
_MAXCOMLEN = 16
_NODEV = 0xFFFFFFFF


class _AuditToken(ctypes.Structure):
    _fields_ = [("val", ctypes.c_uint32 * 8)]


class _AuMask(ctypes.Structure):
    _fields_ = [("am_success", ctypes.c_uint32), ("am_failure", ctypes.c_uint32)]


class _AuTidAddr(ctypes.Structure):
    _fields_ = [("at_port", ctypes.c_int32), ("at_type", ctypes.c_uint32), ("at_addr", ctypes.c_uint32 * 4)]


class _Auditinfo(ctypes.Structure):
    _fields_ = [
        ("ai_auid", ctypes.c_uint32),
        ("ai_mask", _AuMask),
        ("ai_termid", _AuTidAddr),
        ("ai_asid", ctypes.c_int32),
        ("ai_flags", ctypes.c_uint64),
    ]


class _ProcBsdInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * _MAXCOMLEN),
        ("pbi_name", ctypes.c_char * (2 * _MAXCOMLEN)),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


_libproc = ctypes.CDLL(ctypes.util.find_library("proc") or "libproc.dylib", use_errno=True)
_libproc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
_libproc.proc_pidinfo.restype = ctypes.c_int

_libbsm = ctypes.CDLL("/usr/lib/libbsm.dylib", use_errno=True)
_libbsm.audit_token_to_pid.argtypes = [_AuditToken]
_libbsm.audit_token_to_pid.restype = ctypes.c_int
_libbsm.audit_token_to_asid.argtypes = [_AuditToken]
_libbsm.audit_token_to_asid.restype = ctypes.c_int
_libbsm.getaudit_addr.argtypes = [ctypes.POINTER(_Auditinfo), ctypes.c_int]
_libbsm.getaudit_addr.restype = ctypes.c_int


def _bsdinfo(pid: int) -> _ProcBsdInfo:
    """Raises ProcessLookupError (via OSError's errno-based subclassing) if
    `pid` no longer exists."""
    info = _ProcBsdInfo()
    n = _libproc.proc_pidinfo(pid, _PROC_PIDTBSDINFO, 0, ctypes.byref(info), ctypes.sizeof(info))
    if n <= 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    if n != ctypes.sizeof(info):
        raise exceptions.Error(f"short read from proc_pidinfo for pid {pid}: {n} != {ctypes.sizeof(info)}")
    return info


def _start_key(info: _ProcBsdInfo) -> int:
    """A process's start time as one deterministic int -- combined with the
    PID, a stable, kernel-issued identity for one specific process instance:
    the same PID reused by a later process gets a different start_key.
    Verified stable across execve() (same pid, same value pre/post exec)."""
    return info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec


def process_starttime(pid: int) -> int:
    return _start_key(_bsdinfo(pid))


@dataclasses.dataclass(frozen=True)
class Anchor:
    """A pinned, kernel-verified process instance, watchable for exit.

    `kq`'s underlying kqueue fd (exposed as `.fd`) is EVFILT_PROC/NOTE_EXIT-
    registered on `pid` and is select()-able exactly like a Linux pidfd:
    readable the instant the process exits, and still readable on repeated
    non-destructive peeks after that (verified empirically) -- never call
    `kq.control()` to drain it, since retrieving the exit event makes it
    read as *not* readable again, i.e. a dead anchor would read as alive.
    Module-internal (`peercred` never exposes it beyond `.fd`), just not
    underscore-prefixed: pyright's strict-mode private-name check treats a
    leading underscore as accessible only from inside the class body, which
    `close_anchor()` below -- necessarily a module function, not a method,
    to keep this dataclass's shape parity with `_linux.py`'s -- is not.

    Unlike a pidfd, the kqueue fd itself carries no comparable process
    identity -- `(pid, start_key)` is that identity, verified once at
    construction (see `_pin()`) and trusted for the Anchor's lifetime. `kq`
    must be kept referenced for exactly that lifetime: Python's
    `select.kqueue` closes its fd when garbage collected (verified
    empirically), so letting it go out of scope silently invalidates `.fd`.
    """

    pid: int
    start_key: int
    kq: select.kqueue = dataclasses.field(repr=False)

    @property
    def fd(self) -> int:
        return self.kq.fileno()


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    pid: int
    start_key: int
    asid: int | None


def peer_identity(conn: socket.socket) -> PeerIdentity:
    """Kernel-verified (pid, start_key, asid) for the process on the other
    end of `conn`.

    pid and asid come from one `LOCAL_PEERTOKEN` read of the peer's Mach
    audit token; start_key is a second, immediately-following `proc_pidinfo`
    call by that pid -- the same tight, accepted TOCTOU window `_linux.py`
    documents for its own SO_PEERCRED -> pidfd_open gap.
    """
    raw_token = conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERTOKEN, struct.calcsize("8I"))
    token = _AuditToken(val=(ctypes.c_uint32 * 8)(*struct.unpack("8I", raw_token)))
    pid = _libbsm.audit_token_to_pid(token)
    raw_asid = _libbsm.audit_token_to_asid(token)
    asid = None if raw_asid < 0 else raw_asid
    try:
        start_key = process_starttime(pid)
    except ProcessLookupError as e:
        raise exceptions.Error(f"Peer process {pid} exited before its identity could be verified") from e
    return PeerIdentity(pid=pid, start_key=start_key, asid=asid)


def close_peer_identity(_peer: PeerIdentity) -> None:
    pass


def same_process(peer: PeerIdentity, anchor: Anchor) -> bool:
    return peer.pid == anchor.pid and peer.start_key == anchor.start_key


def _controlling_tty_dev(pid: int) -> int | None:
    tty_dev = _bsdinfo(pid).e_tdev
    return None if tty_dev == _NODEV else tty_dev


def peer_session_facts(_conn: socket.socket, peer: PeerIdentity) -> tuple[int | None, int | None]:
    return peer.asid, _controlling_tty_dev(peer.pid)


def _self_audit_session_id() -> int | None:
    info = _Auditinfo()
    rc = _libbsm.getaudit_addr(ctypes.byref(info), ctypes.sizeof(info))
    if rc != 0:
        errno = ctypes.get_errno()
        raise exceptions.Error(f"getaudit_addr() failed: {os.strerror(errno)}")
    return None if info.ai_asid < 0 else info.ai_asid


def parent_session_id(_pid: int) -> int | None:
    """The BSM audit session id session.py should pin as the anchor's.

    Unlike Linux's `/proc/<pid>/sessionid`, an arbitrary pid's asid cannot be
    read unprivileged on Darwin: `auditon(A_GETPINFO_ADDR)` returns EPERM for
    any pid but the caller's own (verified empirically). So this reads *our
    own* asid instead of `_pid`'s (the parent's) -- correct because a BSM
    asid is inherited across fork and unchanged unless a process explicitly
    calls `setaudit_addr()`, which a login shell spawning `pf login` does
    not, so `pf login`'s own asid equals its parent's (verified empirically:
    same value from `getaudit_addr()` in parent and child across a plain
    fork). `_pid` is accepted anyway to keep this call-compatible with
    `_linux.py`'s by-pid version.
    """
    return _self_audit_session_id()


def parent_tty_dev(pid: int) -> int | None:
    """Unlike the audit session id, a controlling tty is readable for any
    same-user pid via `proc_pidinfo` -- no privilege restriction here."""
    return _controlling_tty_dev(pid)


def parent_is_launcher() -> bool:
    """True if our immediate parent is a known dev launcher (uv/uvx/python).

    Best-effort: any failure to read the parent's comm (parent already gone,
    a permission/EPERM) is False -- "no warning" -- never an error. See
    `is_launcher_name`.
    """
    try:
        return _linux.is_launcher_name(_bsdinfo(os.getppid()).pbi_comm.decode())
    except (OSError, exceptions.Error):
        return False


def is_descendant_of(pid: int, anchor: Anchor, *, max_depth: int = 64) -> bool:
    """Walk `pid`'s ancestors looking for the process pinned by `anchor`.

    Each hop reads the current ancestor's own (pid, start_key) immediately
    after learning its pid from its child's `pbi_ppid` -- before anything
    else happens with that pid -- narrowing (not eliminating) the window for
    a recycled pid to be substituted in underneath us; a false accept would
    additionally require the recycled process to coincidentally reuse the
    exact `start_key` of the real anchor, judged acceptable for the same
    reason `_linux.py`'s equivalent gap is.

    Does not check `pid` itself against the anchor -- callers that want
    "anchor or a descendant of it" should check same_process() separately
    first.

    Unlike `/proc`, `proc_pidinfo()` raises PermissionError (not just
    ProcessLookupError) for a pid owned by a different user -- e.g. the walk
    crossing into a root-owned session leader on the way to launchd. Treated
    the same as the walk losing the trail: verified empirically that
    `_linux.py`'s equivalent walk keeps going all the way to pid 1 regardless
    of ownership (procfs's PPid field is world-readable), so this is a real
    platform difference, not a bug to route around -- an ancestor we cannot
    positively identify must not be treated as a match, fail closed.
    """
    current = pid
    for _ in range(max_depth):
        try:
            ppid = int(_bsdinfo(current).pbi_ppid)
        except (ProcessLookupError, PermissionError):
            return False
        if ppid == 0:
            return False
        try:
            ppid_info = _bsdinfo(ppid)
        except (ProcessLookupError, PermissionError):
            return False
        if ppid == anchor.pid and _start_key(ppid_info) == anchor.start_key:
            return True
        current = ppid
    return False


def _pin(pid: int, *, expected_start_key: int | None) -> Anchor:
    kq = select.kqueue()
    try:
        event = select.kevent(pid, filter=select.KQ_FILTER_PROC, flags=select.KQ_EV_ADD, fflags=select.KQ_NOTE_EXIT)
        kq.control([event], 0)
    except ProcessLookupError as e:
        kq.close()
        raise exceptions.Error(f"Anchor process {pid} exited before it could be pinned") from e
    try:
        start_key = process_starttime(pid)
    except ProcessLookupError as e:
        kq.close()
        raise exceptions.Error(f"Anchor process {pid} exited before its identity could be verified") from e
    if expected_start_key is not None and start_key != expected_start_key:
        kq.close()
        raise exceptions.Error(f"Anchor process {pid} identity changed before the oracle could pin it")
    return Anchor(pid=pid, start_key=start_key, kq=kq)


def open_anchor(pid: int) -> Anchor:
    return _pin(pid, expected_start_key=None)


def close_anchor(anchor: Anchor) -> None:
    """The kqueue watch never crosses to the child (`anchor_extra_fds()`
    returns none for Darwin, unlike Linux's pidfd) -- the parent's own copy
    is dead weight once the child has re-registered its own via
    `reconstruct_anchor()`, so release it here."""
    anchor.kq.close()


def anchor_extra_fds(_anchor: Anchor) -> tuple[int, ...]:
    """A kqueue fd does not survive fork/exec (verified empirically), so
    nothing rides along via `pass_fds` for a Darwin anchor -- the spawned
    child re-registers its own watch instead, from the (pid, start_key) in
    `anchor_spawn_token()`'s argv token. See spawn.py."""
    return ()


def anchor_spawn_token(anchor: Anchor, extra_fds: tuple[int, ...]) -> str:
    assert extra_fds == (), f"Darwin anchors carry no extra fds, got {extra_fds!r}"
    return f"pidstart:{anchor.pid}:{anchor.start_key}"


def reconstruct_anchor(token: str) -> Anchor:
    """Rebuild the `Anchor` a spawning process encoded with
    `anchor_spawn_token()`, from inside the spawned child -- see
    _runner.py. Registers a fresh watch on `pid` and then verifies its
    start_key still matches: if the pid had been continuously held by the
    same process from the spawner's read up to this registration (true
    whenever the anchor process is still alive, since pids aren't recycled
    out from under a live process), the watch is provably on the right
    process. Reversed -- verify then watch -- would let a pid recycled in
    between silently end up watched instead."""
    kind, pid_str, start_key_str = token.split(":", 2)
    assert kind == "pidstart", f"unexpected anchor token kind on Darwin: {kind!r}"
    return _pin(int(pid_str), expected_start_key=int(start_key_str))
