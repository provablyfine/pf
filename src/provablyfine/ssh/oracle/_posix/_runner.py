"""Oracle subprocess entry point -- run as `python -m provablyfine.ssh.oracle._posix._runner`.

Never invoked directly; `spawn.spawn_subprocess()` execs into this via
`subprocess.Popen`. Everything the oracle needs -- the listening socket, the
anchor, the private key, the identities, which authorization model to use --
crosses via inherited file descriptors (`pass_fds`) and argv, since this runs
as a fresh Python interpreter, not a forked copy of the spawning process's
memory: there is no shared memory to inherit a Python closure or object
through.

argv: mode sock_fd anchor_token key_pipe_fd ttl_deadline socket_path
      session_id tty_dev
  - mode: "connection" or "session" -- which of connection.authorize /
    session.authorize to reconstruct and run.
  - anchor_token: platform-dependent, opaque to this module --
    `peercred.reconstruct_anchor()` is what knows how to read it (a pass_fds'd
    fd number on Linux; a plain `(pid, start_key)` pair on Darwin, which
    re-registers its own liveness watch from it instead of inheriting one --
    see `peercred/_darwin.py`'s module docstring for why).
  - session_id, tty_dev: "-" for None, a decimal int otherwise. Meaningless
    (but still present, as "-") for mode "connection".

The private key and identity blobs are read from `key_pipe_fd`, a pipe whose
write end the spawner already closed after writing exactly one buffer.Writer
payload: string(key PEM) + uint32(identity count) + that many string(raw
identity blob), all signed by the same key.

Before any of that, `_lock_down()` makes this process's memory unreadable to
other processes of the same user, so the key is only ever readable by the key's
own future readers (see `.._win32.spawn` for the Windows equivalent).
"""

from __future__ import annotations

import ctypes
import os
import resource
import socket
import sys

from .... import jwk
from ... import buffer
from . import connection, peercred, server, session

# Linux: `prctl` option for turning off the dumpable flag.
_PR_SET_DUMPABLE = 4
# Darwin: the `ptrace` request that denies future attaches.
_PT_DENY_ATTACH = 31


def _lock_down() -> None:
    """Make this process's memory unreadable from outside, before the key
    arrives.

    Without this, any process of the same user could read the key straight out
    of our address space: `ptrace`/`/proc/<pid>/mem` on a Linux box with no
    Yama `ptrace_scope`, plain `ptrace` on macOS, and a core dump on both. The
    oracle's stated goal -- a process outside the login shell cannot *use* the
    key -- requires this step, since nothing else stops such a process from
    simply *reading* the key instead.

    - `RLIMIT_CORE` to 0: no core dump can ever contain the key.
    - Linux `PR_SET_DUMPABLE` off: non-dumpable processes cannot be ptraced or
      memory-read by same-user processes, and never dump core either. Root
      remains able to, exactly as ssh-agent's own boundary assumes.
    - macOS `PT_DENY_ATTACH`: the platform's only anti-debugger primitive; it
      makes attaches fail rather than making the process non-dumpable, so
      `RLIMIT_CORE` still matters here.

    Failures are fatal on purpose: a partially locked-down oracle would
    silently hold a readable key, which is precisely the state callers think
    they are not in.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "linux":
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError("PR_SET_DUMPABLE")
    elif sys.platform == "darwin":
        if libc.ptrace(_PT_DENY_ATTACH, 0, None, 0) != 0:
            raise OSError("PT_DENY_ATTACH")


def _read_key_material(read_fd: int) -> tuple[jwk.Private, list[bytes]]:
    with os.fdopen(read_fd, "rb") as f:
        data = f.read()
    reader = buffer.Reader(data)
    key = jwk.Private.from_pem(reader.read_string())
    identity_count = reader.read_uint32()
    raws = [reader.read_string() for _ in range(identity_count)]
    return key, raws


def _optional_int(value: str) -> int | None:
    return None if value == "-" else int(value)


def main() -> None:
    _lock_down()

    mode = sys.argv[1]
    sock_fd = int(sys.argv[2])
    anchor_token = sys.argv[3]
    key_pipe_fd = int(sys.argv[4])
    ttl_deadline = float(sys.argv[5])
    socket_path = sys.argv[6]
    session_id = _optional_int(sys.argv[7])
    tty_dev = _optional_int(sys.argv[8])

    key, raws = _read_key_material(key_pipe_fd)
    identities = [server.Identity(raw=raw, key=key) for raw in raws]
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=sock_fd)
    anchor = peercred.reconstruct_anchor(anchor_token)

    if mode == "connection":
        authorize = connection.authorize(anchor)
    elif mode == "session":
        authorize = session.authorize(anchor, session_id, tty_dev)
    else:
        raise ValueError(f"unknown oracle mode: {mode}")

    own_stat = os.fstat(sock.fileno())
    try:
        server.serve_forever(sock, authorize, identities, ttl_deadline=ttl_deadline, anchor=anchor)
    finally:
        try:
            # If another process raced to create the same socket,
            # to relogin, we cannot blindly unlink it.
            if os.path.samestat(os.stat(socket_path), own_stat):
                os.unlink(socket_path)
        except OSError:
            pass
        try:
            os.rmdir(os.path.dirname(socket_path))
        except OSError:
            pass


if __name__ == "__main__":
    main()
