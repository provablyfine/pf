"""Tests for `_runner._lock_down()`: the spawned oracle must hold its key in
memory that a same-user process can neither read nor dump.

These exercise the kernel's answer, not our syscall: an open of
`/proc/<pid>/pagemap` goes through the same ptrace access check that
`ptrace()` and a `/proc/<pid>/mem` read would, so denying it is direct proof
of the boundary rather than of one particular API call succeeding.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
import time

import pytest

from .... import jwk
from ... import serde
from . import peercred, server, spawn

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="pagemap and dumpable are Linux notions")


def _open_pagemap(pid: int) -> bool:
    """Whether this process may open `/proc/<pid>/pagemap`, i.e. whether the
    ptrace-mode read check passes for `pid`."""
    try:
        fd = os.open(f"/proc/{pid}/pagemap", os.O_RDONLY)
    except PermissionError:
        return False
    os.close(fd)
    return True


def _oracle_core_limit_is_zero(pid: int, timeout: float = 10.0) -> bool:
    """Poll `/proc/<pid>/limits` until the oracle's own `setrlimit` is visible,
    so the assertions below never race the child through its startup. `False`
    on timeout, so a lockdown that never ran fails loudly rather than
    spuriously."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/limits") as f:
                for line in f:
                    if line.startswith("Max core file size"):
                        # "Max core file size  <soft>  <hard>  bytes".
                        # A nonzero read just means the child has not run
                        # `setrlimit` yet, so it retries rather than returns.
                        if line.split()[4] == "0":
                            return True
                        break
        except OSError:
            if not _process_alive(pid):
                raise AssertionError(f"oracle pid {pid} died before locking itself down")
        time.sleep(0.05)
    return False


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _spawn_locked_oracle() -> tuple[int, str]:
    """A session oracle anchored on this process, exactly as `pf login`
    spawns one, returning its pid and socket path for teardown."""
    key = jwk.Private.generate_ed25519()
    identity = server.Identity(raw=serde.serialize_public(key.public()), key=key)
    path = os.path.join(tempfile.mkdtemp(prefix="pf-test-"), "s")
    sock = spawn.bind_socket(path, replace=True)
    anchor = peercred.open_anchor(os.getpid())
    pid = spawn.spawn_subprocess(
        sock, path, key, [identity], anchor, 30.0, mode="session", session_id=None, tty_dev=None
    )
    return pid, path


def _cleanup(pid: int, path: str) -> None:
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    directory = os.path.dirname(path)
    try:
        os.unlink(path)
    except OSError:
        pass
    try:
        os.rmdir(directory)
    except OSError:
        pass


def test_the_oracle_locks_its_memory_and_its_core_limit() -> None:
    """`_lock_down()` must outlive both of the same-user reads that matter:
    `/proc/<pid>/pagemap` (the ptrace-mode gate the `ptrace` attach and the
    `/proc/<pid>/mem` read share) and the core-dump limit.

    Both assertions run against a control -- our own plain child, which
    inherits our environment but has locked nothing down. A pagemap open the
    control cannot even perform (a Yama `ptrace_scope` above 1, a security
    module) would make the oracle's denial pass for the wrong reason, so that
    case skips. A core limit the oracle could not exceed (our own already 0)
    would make the limit assertion vacuous, and is prevented by raising our
    limit first: the oracle must bring it back down to 0 on its own.
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    if hard == 0:
        pytest.skip("RLIMIT_CORE is already 0 here, so the oracle's zeroing is untestable")
    resource.setrlimit(resource.RLIMIT_CORE, (hard, hard))
    try:
        control = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            if not _open_pagemap(control.pid):
                pytest.skip("this box denies pagemap opens to same-user children anyway")
            pid, path = _spawn_locked_oracle()
            try:
                assert _oracle_core_limit_is_zero(pid), "the oracle did not zero RLIMIT_CORE"
                assert not _open_pagemap(pid), "the oracle's memory is still readable by the same user"
            finally:
                _cleanup(pid, path)
        finally:
            control.kill()
            control.wait(timeout=30)
    finally:
        resource.setrlimit(resource.RLIMIT_CORE, (soft, hard))
