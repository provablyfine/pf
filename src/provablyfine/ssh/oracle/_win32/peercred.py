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
import sys

from ... import exceptions
from . import _win32api

# `login_shell_identity()`'s walk only has to climb past the interpreter and
# the console-script launcher -- measured at 3 hops. 8 is slack, and bounds a
# walk that would otherwise be at the mercy of a cyclic ppid report.
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


def session_id(pid: int) -> int | None:
    """The Windows (Terminal Services) session id.

    This is a *desktop login*, not a shell: every console under one login
    shares it, so on its own it is far too broad to authorize with. It is only
    ever the second factor, behind the anchored parent process.

    Windows has no third factor to add. Two independently-opened consoles under
    one login share their session id and nothing else
    """
    return _win32api.process_session_id(pid)


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


def _same_file(left: str, right: str) -> bool:
    return os.path.normcase(os.path.realpath(left)) == os.path.normcase(os.path.realpath(right))


def _under(path: str, root: str) -> bool:
    return os.path.normcase(os.path.realpath(path)).startswith(os.path.normcase(os.path.realpath(root)) + os.sep)


def _is_our_own_python(image: str, own_image: str) -> bool:
    """True if `image` is part of the Python installation running this code.

    Two tests, because neither covers the other. The exact-file test catches
    the interpreter itself; the prefix test catches the console-script launcher
    and the venv shim, which live beside the interpreter in `Scripts\\` -- and it
    covers both the venv layout and a system-wide `C:\\Python312\\Scripts\\pf.exe`
    install, where `sys.executable` and the launcher are in *different*
    directories and a "same directory as sys.executable" test would miss it.
    """
    base_executable = getattr(sys, "_base_executable", None)
    exact = [own_image, sys.executable]
    if isinstance(base_executable, str):
        exact.append(base_executable)
    if any(_same_file(image, candidate) for candidate in exact):
        return True
    return _under(image, sys.prefix) or _under(image, sys.base_prefix)


def login_shell_identity() -> tuple[int, int]:
    """The `(pid, creation_time)` of the shell to anchor the session oracle on.

        python3.12.exe            <- us, the real interpreter
        venv\\Scripts\\python.exe   <- the venv shim, == sys.executable
        pf.exe                    <- the console-script launcher
        cmd.exe                   <- the shell we actually want

    So: climb past anything belonging to our own Python installation and anchor
    on the first ancestor that does not.

    Returns both values off the single handle the walk already holds, rather
    than a bare pid, so callers don't re-open the process for the creation time
    and risk the shell exiting between the two reads.
    """
    handle = _open_or_fail(os.getpid(), "Own")
    try:
        own_image = _win32api.process_image_path(handle)
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
            if not _is_our_own_python(image, own_image):
                try:
                    return parent, _win32api.process_creation_time(parent_handle)
                finally:
                    _win32api.close_handle(parent_handle)
            _win32api.close_handle(handle)
            handle, current = parent_handle, parent
        # Ran out of ancestors while still inside our own installation (a
        # bare `python -m ...` from something we can't see, a detached
        # process). Anchoring on ourselves still gives a stable, correct --
        # just narrower -- binding: only this process and its descendants.
        return current, _win32api.process_creation_time(handle)
    finally:
        _win32api.close_handle(handle)
