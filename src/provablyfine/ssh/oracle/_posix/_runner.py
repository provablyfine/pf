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
"""

from __future__ import annotations

import os
import socket
import sys

from .... import jwk
from ... import buffer
from . import connection, peercred, server, session


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

    try:
        server.serve_forever(sock, authorize, identities, ttl_deadline=ttl_deadline, anchor=anchor)
    finally:
        try:
            os.unlink(socket_path)
        except OSError:
            pass
        try:
            os.rmdir(os.path.dirname(socket_path))
        except OSError:
            pass


if __name__ == "__main__":
    main()
