"""Test-only controls over the running session-key oracle.

`socket_exists` and `kill_oracle` have no production caller: they exist so
e2e tests (`test_tui.py`) can simulate an oracle's TTL elapsing without
waiting it out. They live here, not in `provablyfine.ssh.oracle`, so that
package's surface stays production-only.
"""

from __future__ import annotations

import os
import sys

if sys.platform == "win32":
    import time

    import provablyfine.ssh.exceptions
    import provablyfine.ssh.oracle._win32
    import provablyfine.ssh.oracle._win32._win32api
    import provablyfine.ssh.oracle._win32.session

    def socket_exists(path: str) -> bool:
        """Whether an oracle is listening at `path`.

        Not `os.path.exists()`: `GetFileAttributesW`, which backs it, is
        unreliable for named pipes. `_win32api.named_pipe_exists()` uses
        `WaitNamedPipeW` instead, which distinguishes "no such pipe" from "pipe
        exists but every instance is busy" unambiguously.
        """
        return provablyfine.ssh.oracle._win32._win32api.named_pipe_exists(path)

    def kill_oracle(path: str) -> None:
        """Make the calling process's own oracle disappear, the way its TTL
        elapsing would.

        Unlike the posix version below, `path` cannot just be unlinked: a
        named pipe is not independently removable while its server still
        holds the listening handle (`os.remove()` raises `WinError 231`,
        "All pipe instances are busy"). Instead this signals the same
        new-login event a fresh `pf login` would use to evict a predecessor
        (see `session._create_pipe_on_new_login`) -- `serve()`'s watchdog
        thread wakes on it and calls `os._exit()`, which is what actually
        closes the pipe's last handle -- then polls for `path` to stop
        existing, since that exit happens on the oracle's own thread,
        asynchronously to this call.
        """
        pid, creation_time = provablyfine.ssh.oracle._win32.peercred.login_shell_identity()
        event = provablyfine.ssh.oracle._win32._win32api.open_event(
            provablyfine.ssh.oracle._win32.session._new_login_event_name(pid, creation_time)
        )
        if event is None:
            raise provablyfine.ssh.exceptions.Error(f"No session oracle is listening at {path}")
        try:
            provablyfine.ssh.oracle._win32._win32api.set_event(event)
        finally:
            provablyfine.ssh.oracle._win32._win32api.close_handle(event)
        deadline = time.monotonic() + provablyfine.ssh.oracle._win32.session._NEW_LOGIN_TIMEOUT_SECONDS
        while provablyfine.ssh.oracle._win32._win32api.named_pipe_exists(path):
            if time.monotonic() >= deadline:
                raise provablyfine.ssh.exceptions.Error(
                    f"Oracle at {path} did not exit after being signaled to stand down"
                )
            time.sleep(0.02)

else:

    def socket_exists(path: str) -> bool:
        """Whether an oracle is listening at `path`.

        A plain `os.path.exists()`: an AF_UNIX socket is a real filesystem
        entry, unlike its win32 named-pipe counterpart.
        """
        return os.path.exists(path)

    def kill_oracle(path: str) -> None:
        """Make the oracle at `path` disappear, the way its TTL elapsing would.

        A plain `os.remove()`: an AF_UNIX socket path can be unlinked
        independently of its server process, unlike its win32 named-pipe
        counterpart.
        """
        os.remove(path)
