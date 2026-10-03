"""Kernel-verified peer-process identity for the oracle's UNIX-socket peers,
on macOS.

- `LOCAL_PEERTOKEN` under `SOL_LOCAL` returns the connecting
  peer's Mach audit token in one `getsockopt()` call both its real pid
  and its BSM audit session id from `libbsm`.

- `libproc`'s `proc_pidinfo(PROC_PIDTBSDINFO)` gives a process's parent
  pid, controlling-tty device, and start time in one call

- `getpeereid()` is the client's way to ask the same question the audit
  token answers for the server.

- `kqueue`'s `EVFILT_PROC`/`NOTE_EXIT` gives a select()-able fd that becomes
  readable the instant a pinned pid exits.
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

_libc = ctypes.CDLL(None, use_errno=True)
_libc.getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
_libc.getpeereid.restype = ctypes.c_int


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


def _peer_audit_token(conn: socket.socket) -> _AuditToken:
    """The peer's Mach audit token, in one `getsockopt()`.

    Everything the kernel can tell us about who is on the other end of a UNIX
    socket is already in here, so every reader below takes this one call and
    then asks `libbsm` to decode a field of it.
    """
    raw_token = conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERTOKEN, struct.calcsize("8I"))
    return _AuditToken(val=(ctypes.c_uint32 * 8)(*struct.unpack("8I", raw_token)))


def peer_identity(conn: socket.socket) -> PeerIdentity:
    """Kernel-verified (pid, start_key, asid) for the process on the other
    end of `conn`.
    """
    token = _peer_audit_token(conn)
    pid = _libbsm.audit_token_to_pid(token)
    raw_asid = _libbsm.audit_token_to_asid(token)
    asid = None if raw_asid < 0 else raw_asid
    try:
        start_key = process_starttime(pid)
    except ProcessLookupError as e:
        raise exceptions.Error(f"Peer process {pid} exited before its identity could be verified") from e
    return PeerIdentity(pid=pid, start_key=start_key, asid=asid)


def peer_user_id(conn: socket.socket) -> int:
    """The effective uid of the process on the other end of `conn`.

    `getpeereid()`, deliberately not the `LOCAL_PEERTOKEN` audit token
    `peer_identity()` reads. That option answers in one direction and not the
    other: from an oracle to its peer it works, but from a client to a real
    oracle it fails with `EINVAL`.
    """
    euid, _egid = _getpeereid(conn)
    return euid


def _getpeereid(conn: socket.socket) -> tuple[int, int]:
    euid, egid = ctypes.c_uint32(), ctypes.c_uint32()
    rc = _libc.getpeereid(conn.fileno(), ctypes.byref(euid), ctypes.byref(egid))
    if rc != 0:
        raise exceptions.Error(f"getpeereid() failed: {os.strerror(ctypes.get_errno())}")
    return int(euid.value), int(egid.value)


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

    This reads *our own* asid instead of `_pid`'s (the parent's). It is
    correct because a BSM asid is inherited across fork and unchanged
    unless a process explicitly calls `setaudit_addr()`, which a login
    shell spawning `pf login` does not
    """
    return _self_audit_session_id()


def parent_tty_dev(pid: int) -> int | None:
    """Unlike the audit session id, a controlling tty is readable for any
    same-user pid via `proc_pidinfo` -- no privilege restriction here."""
    return _controlling_tty_dev(pid)


def parent_is_launcher() -> bool:
    """True if our immediate parent is a known dev launcher (uv/uvx/python)."""
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
    exact `start_key` of the real anchor.

    Does not check `pid` itself against the anchor -- callers that want
    "anchor or a descendant of it" should check same_process() separately
    first.

    Unlike `/proc`, `proc_pidinfo()` raises PermissionError (not just
    ProcessLookupError) for a pid owned by a different user -- e.g. the walk
    crossing into a root-owned session leader on the way to launchd.
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
    """The kqueue watch never crosses to the child: the parent's own copy
    is dead weight once the child has re-registered its own via
    `reconstruct_anchor()`, so release it here."""
    anchor.kq.close()


def anchor_extra_fds(_anchor: Anchor) -> tuple[int, ...]:
    """A kqueue fd does not survive fork/exec, so
    nothing rides along via `pass_fds` for a Darwin anchor.
    """
    return ()


def anchor_spawn_token(anchor: Anchor, extra_fds: tuple[int, ...]) -> str:
    assert extra_fds == (), f"Darwin anchors carry no extra fds, got {extra_fds!r}"
    return f"pidstart:{anchor.pid}:{anchor.start_key}"


def reconstruct_anchor(token: str) -> Anchor:
    """Rebuild the `Anchor` a spawning process encoded with
    `anchor_spawn_token()`, from inside the spawned child.

    The token is only two numbers, so the child checks them against the
    kernel before trusting them. First it asks the kernel to signal it when
    `pid` exits. A `pid` that is already dead fails that step, so from then
    on no exit of it can be missed.

    Then it reads the start time of `pid` and compares it with the one in
    the token. The kernel hands a pid out again only after the old owner is
    gone, and the new owner gets a new start time. So when the two start
    times match, the process under watch is the exact process instance the
    parent pinned.

    If it dies later, the watch fires. If its pid had already been reused,
    the start times differ and pinning fails. There is no path where the
    anchor silently becomes a different process.
    """
    kind, pid_str, start_key_str = token.split(":", 2)
    assert kind == "pidstart", f"unexpected anchor token kind on Darwin: {kind!r}"
    return _pin(int(pid_str), expected_start_key=int(start_key_str))
