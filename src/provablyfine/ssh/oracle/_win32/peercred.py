"""Kernel-verified peer-process identity for the oracle's named-pipe peers.

The primitives:

- `GetNamedPipeClientProcessId()` is the kernel's own record of who connected.
  Like `SO_PEERCRED`, the client cannot lie about it.
- `OpenProcess()` returns a real kernel object reference rather than a
  recyclable integer -- `WaitForSingleObject` on it stays unsignaled while the
  process lives and signals the instant it exits.
- `GetProcessTimes()`'s creation `FILETIME` is the start-time tiebreaker that
  makes a pid mean something: a recycled pid gets a different creation time.
- `NtQueryInformationProcess(ProcessBasicInformation)` answers "who is this
  process's parent" for a HANDLE we already hold, which is what makes the
  ancestry walk below TOCTOU-safe.

Two things here have no POSIX counterpart, both forced by the platform rather
than chosen: the created-after-child rejection in `is_descendant_of()`, and
`login_shell_identity()`. See their docstrings.
"""

from __future__ import annotations

import dataclasses
import os
import re

from ... import exceptions
from . import _win32api

# `login_shell_identity()`'s walk only has to climb past the interpreter, a
# venv shim, and `uv` -- measured at 3 hops. 8 is slack, and bounds a walk that
# would otherwise be at the mercy of a cyclic ppid report.
_MAX_LAUNCHER_HOPS = 8


@dataclasses.dataclass(frozen=True)
class Anchor:
    """A pinned, kernel-verified process instance, watchable for exit.

    `handle` refers to one specific process object and does not follow pid
    reuse, so waiting on it genuinely tracks the process the anchor was made
    for. `(pid, creation_time)` is the comparable identity, verified once at
    construction and trusted for the Anchor's lifetime -- exactly what
    `_darwin` does with `(pid, start_key)`.
    """

    pid: int
    creation_time: int
    handle: int = dataclasses.field(repr=False)


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    pid: int
    creation_time: int


def is_alive(anchor: Anchor) -> bool:
    """True while the process pinned by `anchor` is still running.

    A process HANDLE signals once at exit and stays signaled
    """
    return _win32api.wait_for_single_object(anchor.handle, 0) == _win32api.WAIT_TIMEOUT


def _open_or_fail(pid: int, what: str) -> int:
    handle = _win32api.open_process(pid)
    if handle is None:
        raise exceptions.Error(
            f"{what} process {pid} could not be opened: {_win32api.last_error_message('OpenProcess')}"
        )
    return handle


def process_starttime(pid: int) -> int:
    handle = _open_or_fail(pid, "Target")
    try:
        return _win32api.process_creation_time(handle)
    finally:
        _win32api.close_handle(handle)


def peer_identity(pipe_handle: int) -> PeerIdentity:
    """Kernel-verified `(pid, creation_time)` for the process on the other end."""
    pid = _win32api.named_pipe_client_pid(pipe_handle)
    handle = _win32api.open_process(pid)
    if handle is None:
        raise exceptions.Error(f"Peer process {pid} exited before its identity could be verified")
    try:
        return PeerIdentity(pid=pid, creation_time=_win32api.process_creation_time(handle))
    finally:
        _win32api.close_handle(handle)


def same_process(peer: PeerIdentity, anchor: Anchor) -> bool:
    return peer.pid == anchor.pid and peer.creation_time == anchor.creation_time


def logon_sid(anchor: Anchor) -> str | None:
    """The login of the anchored process, or None when it cannot be read.

    The second factor behind the anchored parent: a peer must share the
    anchor's login, not just sit under it in the process tree. The logon SID
    is kernel-assigned and unforgeable -- the one thing that separates a
    normal child of the shell from a `runas` child that inherited the tree but
    not the token. None means "unreadable", which callers treat as a missing
    (not a matching) factor.
    """
    return _win32api.logon_sid(anchor.handle)


def logon_sid_of(pid: int) -> str | None:
    """The logon SID of an arbitrary peer process, or None if it cannot be read.

    Used at authorize time to check a connecting peer against the anchor's
    login. The peer is a descendant of our own shell, so opening it with the
    usual limited access should succeed; None means "could not verify", which
    the caller treats as a rejection rather than a match.
    """
    handle = _win32api.open_process(pid)
    if handle is None:
        return None
    try:
        return _win32api.logon_sid(handle)
    finally:
        _win32api.close_handle(handle)


def is_descendant_of(pid: int, anchor: Anchor, *, max_depth: int = 64) -> bool:
    """Walk `pid`'s ancestors looking for the process pinned by `anchor`.

    Each hop opens a HANDLE to the current process *first* and reads its parent
    pid through that handle. The handle pins the process object, so the parent
    pid cannot be read out from under us by something that recycled the pid.

    Note: Windows never reparents orphans. When a parent exits, its children
    go on reporting its now-meaningless pid, which the OS is free to hand to
    something else.
    """
    handle = _win32api.open_process(pid)
    if handle is None:
        return False
    try:
        for _ in range(max_depth):
            try:
                created = _win32api.process_creation_time(handle)
                parent = _win32api.process_parent_pid(handle)
            except exceptions.Error:
                return False
            if parent == 0:
                return False
            parent_handle = _win32api.open_process(parent)
            if parent_handle is None:
                return False
            try:
                parent_created = _win32api.process_creation_time(parent_handle)
            except exceptions.Error:
                _win32api.close_handle(parent_handle)
                return False
            if parent_created > created:
                # A recycled pid: this "parent" started after its claimed
                # child, so the real parent is gone and the trail is dead.
                _win32api.close_handle(parent_handle)
                return False
            if parent == anchor.pid and parent_created == anchor.creation_time:
                _win32api.close_handle(parent_handle)
                return True
            _win32api.close_handle(handle)
            handle = parent_handle
        return False
    finally:
        _win32api.close_handle(handle)


def _pin(pid: int, *, expected_creation_time: int | None) -> Anchor:
    """Open a handle to `pid`, and only then verify its identity.

    Order matters, exactly as in `_darwin._pin()`: the handle pins the process
    object first, so if the identity check then passes, the handle is provably
    on the right process. Verifying first and opening second would let a pid
    recycled in between end up pinned instead.
    """
    handle = _open_or_fail(pid, "Anchor")
    try:
        creation_time = _win32api.process_creation_time(handle)
        if expected_creation_time is not None and creation_time != expected_creation_time:
            raise exceptions.Error(f"Anchor process {pid} identity changed before the oracle could pin it")
    except exceptions.Error:
        _win32api.close_handle(handle)
        raise
    return Anchor(pid=pid, creation_time=creation_time, handle=handle)


def open_anchor(pid: int) -> Anchor:
    return _pin(pid, expected_creation_time=None)


def close_anchor(anchor: Anchor) -> None:
    _win32api.close_handle(anchor.handle)


def anchor_spawn_token(anchor: Anchor) -> str:
    """How an anchor crosses into the spawned oracle subprocess: a plain
    `(pid, creation_time)` pair in argv, like Darwin's.

    Nothing is inherited. Unlike Linux's pidfd, a process HANDLE would have to
    be marked inheritable and threaded through `STARTUPINFO`, and there is no
    reason to -- re-opening in the child is both simpler and verifiable.
    """
    return f"pidstart:{anchor.pid}:{anchor.creation_time}"


def reconstruct_anchor(token: str) -> Anchor:
    """Rebuild the `Anchor` encoded by `anchor_spawn_token()`, inside the
    spawned child. Opens a fresh handle and *then* checks the creation time
    still matches -- see `_pin()` for why that order is the safe one."""
    kind, pid_text, creation_text = token.split(":", 2)
    if kind != "pidstart":
        raise exceptions.Error(f"unexpected anchor token kind on Windows: {kind!r}")
    return _pin(int(pid_text), expected_creation_time=int(creation_text))


def _is_launcher(image: str) -> bool:
    stem = os.path.basename(image).lower()
    if stem.endswith(".exe"):
        stem = stem[:-4]

    # The Python interpreter, plain or windowed: `python.exe` / `pythonw.exe`.
    if stem == "python" or stem == "pythonw":
        return True

    # A versioned interpreter: `python3.exe`, `python312.exe`, `python3.12.exe`.
    # "python" plus digits and dots only.
    if stem.startswith("python") and _is_versioned_suffix(stem[len("python") :]):
        return True

    # PyPy: `pypy.exe`, and versioned `pypy3.exe` / `pypy3.10.exe`.
    if stem == "pypy":
        return True
    if stem.startswith("pypy") and _is_versioned_suffix(stem[len("pypy") :]):
        return True

    # The `py` / `pyw` launcher.
    if stem == "py" or stem == "pyw":
        return True

    # `uv` and its tool runner `uvx`.
    if stem == "uv" or stem == "uvx":
        return True

    return False


_VERSIONED_SUFFIX_RE = re.compile(r"[0-9.]+")


def _is_versioned_suffix(suffix: str) -> bool:
    """Whether the part after a `python`/`pypy` prefix is only digits and dots
    (a version, e.g. `.12`, `3`, `3.12`)."""
    return _VERSIONED_SUFFIX_RE.fullmatch(suffix) is not None


def login_shell_identity() -> tuple[int, int]:
    """The `(pid, creation_time)` of the shell to anchor the session oracle on.

        python3.12.exe            <- us, the real interpreter (a launcher)
        venv\\Scripts\\python.exe   <- the venv shim (a launcher)
        uv.exe                    <- a launcher (e.g. `uv run`)
        cmd.exe                   <- the shell: stop, anchor here

    This process is a launcher by construction -- `login_shell_identity()`
    runs inside the Python interpreter, whether that interpreter was started
    as `python.exe`, a `venv` shim, or a `console_scripts` copy renamed to
    `pf.exe`. So we skip ourselves and climb while an *ancestor* is still a
    launcher, stopping at the first non-launcher: the shell that every later
    `pf`/`pfa` invocation from the same login shares, and which lives for the
    whole login. That is exactly what POSIX gets from `getppid()`.

    The first non-Python ancestor is *not* the shell: under `uv run` it is the
    short-lived `uv.exe` launcher, which exits before the session oracle has
    finished serving (killing the oracle via its anchor-exit watchdog). Hence
    the skip past `uv` too.

    Returns both values off the single handle the walk already holds, rather
    than a bare pid, so callers don't re-open the process for the creation time
    and risk the shell exiting between the two reads.
    """
    handle = _open_or_fail(os.getpid(), "Own")
    try:
        current = os.getpid()
        for _ in range(_MAX_LAUNCHER_HOPS):
            parent = _win32api.process_parent_pid(handle)
            if parent == 0:
                break
            parent_handle = _win32api.open_process(parent)
            if parent_handle is None:
                break
            try:
                image = _win32api.process_image_path(parent_handle)
            except exceptions.Error:
                _win32api.close_handle(parent_handle)
                break
            if _is_launcher(image):
                _win32api.close_handle(handle)
                handle, current = parent_handle, parent
                continue
            try:
                # The parent is not a launcher: it is the shell we anchor on.
                return parent, _win32api.process_creation_time(parent_handle)
            finally:
                _win32api.close_handle(parent_handle)
        # Every ancestor we could see was a launcher (a deep `python` nesting,
        # a detached process). Anchoring on the deepest process we reached
        # still gives a stable, correct -- just narrower -- binding: this
        # process and its descendants.
        return current, _win32api.process_creation_time(handle)
    finally:
        _win32api.close_handle(handle)
