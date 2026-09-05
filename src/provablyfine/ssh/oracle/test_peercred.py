"""Pure unit tests for peercred.py's ancestry walk -- real subprocess chains,
no mocks, no server involved (per CLAUDE.md's "avoid the use of mocks")."""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time

import pytest

from . import peercred

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="peercred is Linux-only")

_HELPER = pathlib.Path(__file__).with_name("_test_ancestry_helper.py")


def _wait_for(path: pathlib.Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, f"timed out waiting for {path}"
        time.sleep(0.05)


def test_is_descendant_of_matches_a_real_3_deep_descendant(tmp_path: pathlib.Path) -> None:
    pid_file = tmp_path / "pid"
    ready_file = tmp_path / "ready"
    proc = subprocess.Popen([sys.executable, str(_HELPER), "3", str(pid_file), str(ready_file)])  # noqa: S603
    try:
        _wait_for(ready_file)
        leaf_pid = int(pid_file.read_text())

        anchor_pidfd = os.pidfd_open(os.getpid())
        try:
            assert peercred.is_descendant_of(leaf_pid, anchor_pidfd)
        finally:
            os.close(anchor_pidfd)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_is_descendant_of_rejects_an_unrelated_sibling_process() -> None:
    sibling_a = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    sibling_b = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        # Both are direct children of *this* test process -- siblings of each
        # other, neither an ancestor of the other -- so pinning sibling_a as
        # the anchor must not match sibling_b's ancestry (which is: this test
        # process, the pytest runner, ..., not sibling_a).
        anchor_pidfd = os.pidfd_open(sibling_a.pid)
        try:
            assert not peercred.is_descendant_of(sibling_b.pid, anchor_pidfd)
        finally:
            os.close(anchor_pidfd)
    finally:
        sibling_a.terminate()
        sibling_b.terminate()
        sibling_a.wait(timeout=5)
        sibling_b.wait(timeout=5)


def test_pidfd_same_process_identity() -> None:
    a = os.pidfd_open(os.getpid())
    b = os.pidfd_open(os.getpid())
    try:
        assert peercred.pidfd_same_process(a, b)
    finally:
        os.close(a)
        os.close(b)


def test_pidfd_same_process_rejects_different_processes() -> None:
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        mine = os.pidfd_open(os.getpid())
        theirs = os.pidfd_open(other.pid)
        try:
            assert not peercred.pidfd_same_process(mine, theirs)
        finally:
            os.close(mine)
            os.close(theirs)
    finally:
        other.terminate()
        other.wait(timeout=5)


def test_pidfd_is_alive() -> None:
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    pidfd = os.pidfd_open(proc.pid)
    try:
        assert peercred.pidfd_is_alive(pidfd)
        proc.terminate()
        proc.wait(timeout=5)
        deadline = time.monotonic() + 5
        while peercred.pidfd_is_alive(pidfd) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not peercred.pidfd_is_alive(pidfd)
    finally:
        os.close(pidfd)
