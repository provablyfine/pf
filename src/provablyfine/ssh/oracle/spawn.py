"""Shared socket-setup and subprocess-spawn helper for both oracle models.

Sequence, used identically by connection.py and session.py:
1. Caller creates+binds+listens the UNIX socket (`bind_socket`) *before*
   spawning -- eliminates any "is the oracle up yet" race: the socket is
   already accept-ready before the parent proceeds.
2. Caller computes its authorization anchor (a `peercred.Anchor`) *before*
   calling here.
3. `spawn_subprocess` writes the private key and identity blobs to a pipe,
   then `subprocess.Popen`s a fresh interpreter running `_runner.py` as
   `__main__`, with the listening socket and the read end of that pipe
   passed via `pass_fds`, plus whatever `peercred.anchor_extra_fds()` says
   the anchor itself needs (a pidfd on Linux; nothing on Darwin -- see
   `peercred/_darwin.py`'s module docstring for why). The runner
   reconstructs everything from those fds plus argv and runs the accept
   loop -- see `_runner.py`'s module docstring for the wire format.
4. In the parent, `spawn_subprocess` closes its own copies of the socket,
   the anchor, and the pipe fds, and returns immediately -- callers don't
   manage any of their lifetimes themselves.

Why subprocess, not `os.fork()`: this package's callers can be running with
other threads alive at the moment a key is minted -- Textual's worker
threads in the TUI, background threads in some test harnesses. Forking a
multithreaded process risks inheriting a C-level lock (malloc arena, the
import lock, a logging handler's lock, ...) in a permanently-stuck state,
since only the forking thread's stack survives into the child while whatever
lock state existed at that instant does too. `subprocess.Popen`'s internal
fork+exec (or `posix_spawn`, when conditions allow) doesn't have this
hazard: `exec()` replaces the process image immediately, before any
inherited lock state could ever be touched by the new program.

The tradeoff: the private key can no longer ride along as a shared Python
object the way it would across a fork (a `Popen`-spawned child is a fresh
interpreter, not a copy of this process's memory) -- it crosses through a
pipe instead, `pass_fds`'d exactly like the listening socket. Still
kernel-buffered only, never touches disk, same guarantee as before.
"""

from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
import time
import typing

from ... import jwk
from .. import buffer, exceptions
from . import peercred, server

_SUPPORTED_PLATFORMS = ("linux", "darwin")


def require_platform_supported() -> None:
    """Raise a clear, catchable error on any platform without a peercred backend.

    Called at the top of every oracle entry point (`connection.spawn_oracle`,
    `session.spawn_oracle`, `session.current_socket_path`) rather than at
    module-import time, so that merely importing `provablyfine.ssh` -- which
    happens on every platform, including ones the oracle doesn't support --
    never crashes. See `peercred/_linux.py` and `peercred/_darwin.py`'s
    module docstrings for the platform-specific primitives each is built on.
    """
    if sys.platform not in _SUPPORTED_PLATFORMS:
        raise exceptions.Error("The peer-credential signing oracle only supports Linux and macOS")


def bind_socket(path: str, *, replace: bool = False) -> socket.socket:
    """Create, bind, and listen() a UNIX socket at `path`.

    `path`'s parent directory is created 0700 if missing; the socket file
    itself is 0600 -- both belt-and-braces behind the actual security
    boundary, which is peer-credential verification at accept(), not
    filesystem permissions.

    If `path` already exists, behavior depends on `replace`:
    - `replace=False` (connection key: a fresh, per-invocation random path --
      a collision here is essentially impossible, so treat one as suspicious):
      only steal the path if nothing is actually listening on it (a stale
      leftover from an oracle that didn't get to unlink it, e.g. a hard
      kill), confirmed by probing with a real connect attempt.
    - `replace=True` (session key: a deterministic, derived-not-secret path
      -- see session.py's module docstring): unconditionally unlink and
      rebind, live listener or not. A collision here can only mean this same
      shell already has a session oracle running from an earlier `pf login`,
      which a new `pf login` is supposed to supersede -- not something to
      politely fail on. The superseded oracle, if still alive, simply keeps
      running unreachably by path until its own TTL/anchor check ends it;
      nothing connects to it again since the config was already updated to
      the new session key.
    """
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(path)
    except OSError as e:
        if e.errno != errno.EADDRINUSE or not (replace or _is_stale(path)):
            sock.close()
            raise
        os.unlink(path)
        sock.bind(path)
    os.chmod(path, 0o600)
    sock.listen(5)
    return sock


def _is_stale(path: str) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(path)
    except OSError:
        return True
    else:
        probe.close()
        return False


def _dup_above_stdio(fd: int) -> int:
    """Return an fd number > 2 for the same open file description as `fd`,
    relocating it if `fd` itself is 0, 1, or 2.

    `Popen(stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL, pass_fds=...)`
    dup2()s /dev/null onto exactly 0/1/2 in the child. If an fd we're
    pass_fds'ing already happened to *be* 0, 1, or 2 in the parent (only
    possible if something upstream already closed a real stdio fd, freeing
    the kernel to hand that low number back out to us), that dup2 silently
    clobbers it before the child ever sees it -- confirmed empirically: the
    child read the devnull-redirected b'' instead of the intended pipe data.
    Since the runner's own stderr goes to devnull too, a collision like this
    would fail silently rather than raise. Cheap enough to just make
    impossible rather than merely guard against.
    """
    if fd > 2:
        return fd
    new_fd = os.dup(fd)
    os.close(fd)
    return new_fd


def spawn_subprocess(
    sock: socket.socket,
    socket_path: str,
    key: jwk.Private,
    identities: list[server.Identity],
    anchor: peercred.Anchor,
    ttl: float,
    mode: typing.Literal["connection", "session"],
    *,
    session_id: int | None = None,
    tty_dev: int | None = None,
) -> None:
    """Spawn the oracle as a subprocess running `_runner.py`; the parent
    returns immediately, the child runs the accept loop until it self-
    terminates (TTL expiry or anchor process exit).

    `mode` is `"connection"` or `"session"` -- which of `connection.authorize`
    / `session.authorize` the runner reconstructs and uses; `session_id`/
    `tty_dev` are only meaningful (and required) for `"session"`.

    How `anchor` crosses into the child is platform-dependent (a pidfd rides
    along via `pass_fds` on Linux; nothing does on Darwin, which re-derives
    its own watch from a plain `(pid, start_key)` argv token instead) -- see
    `peercred.anchor_extra_fds()`/`anchor_spawn_token()`/`reconstruct_anchor()`.
    """
    ttl_deadline = time.monotonic() + ttl
    read_fd, write_fd = os.pipe()
    try:
        payload = buffer.Writer()
        payload.write_string(key.to_pem())
        payload.write_uint32(len(identities))
        for identity in identities:
            payload.write_string(identity.raw)
        os.write(write_fd, payload.to_bytes())
    finally:
        os.close(write_fd)

    if sock.fileno() <= 2:
        family, sock_type = sock.family, sock.type
        old_fd = sock.detach()
        sock = socket.socket(family, sock_type, fileno=_dup_above_stdio(old_fd))
    anchor_fds = tuple(_dup_above_stdio(fd) for fd in peercred.anchor_extra_fds(anchor))
    anchor_token = peercred.anchor_spawn_token(anchor, anchor_fds)
    read_fd = _dup_above_stdio(read_fd)

    argv = [
        sys.executable,
        "-m",
        "provablyfine.ssh.oracle._runner",
        mode,
        str(sock.fileno()),
        anchor_token,
        str(read_fd),
        str(ttl_deadline),
        socket_path,
        "-" if session_id is None else str(session_id),
        "-" if tty_dev is None else str(tty_dev),
    ]
    subprocess.Popen(  # noqa: S603
        argv,
        pass_fds=(sock.fileno(), *anchor_fds, read_fd),
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    sock.close()
    for fd in anchor_fds:
        os.close(fd)
    peercred.close_anchor(anchor)
    os.close(read_fd)
