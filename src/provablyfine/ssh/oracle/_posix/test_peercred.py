"""Pure unit tests for peercred's ancestry walk and anchor primitives."""

from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import sys
import time

import pytest

from . import peercred

pytestmark = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="oracle only supports Linux and macOS")

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

        anchor = peercred.open_anchor(os.getpid())
        try:
            assert peercred.is_descendant_of(leaf_pid, anchor)
        finally:
            peercred.close_anchor(anchor)
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
        anchor = peercred.open_anchor(sibling_a.pid)
        try:
            assert not peercred.is_descendant_of(sibling_b.pid, anchor)
        finally:
            peercred.close_anchor(anchor)
    finally:
        sibling_a.terminate()
        sibling_b.terminate()
        sibling_a.wait(timeout=5)
        sibling_b.wait(timeout=5)


def test_same_process_identity() -> None:
    anchor = peercred.open_anchor(os.getpid())
    try:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer = peercred.peer_identity(a)
            try:
                assert peercred.same_process(peer, anchor)
            finally:
                peercred.close_peer_identity(peer)
        finally:
            a.close()
            b.close()
    finally:
        peercred.close_anchor(anchor)


def test_same_process_rejects_different_processes() -> None:
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        theirs = peercred.open_anchor(other.pid)
        try:
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                peer = peercred.peer_identity(a)  # this is *our own* identity, not `other`'s
                try:
                    assert not peercred.same_process(peer, theirs)
                finally:
                    peercred.close_peer_identity(peer)
            finally:
                a.close()
                b.close()
        finally:
            peercred.close_anchor(theirs)
    finally:
        other.terminate()
        other.wait(timeout=5)


def test_is_launcher_name() -> None:
    launchers = [
        "uv",
        "uvx",
        "/usr/bin/uv",
    ]
    non_launchers = ["bash", "sh", "fish", "zsh", "ksh", "dash", "sshd", "cmd", "tmux", "screen"]
    for name in launchers:
        assert peercred._linux.is_launcher_name(name), f"{name!r} should be a launcher"
    for name in non_launchers:
        assert not peercred._linux.is_launcher_name(name), f"{name!r} should not be a launcher"


def test_is_alive() -> None:
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    anchor = peercred.open_anchor(proc.pid)
    try:
        assert peercred.is_alive(anchor)
        proc.terminate()
        proc.wait(timeout=5)
        deadline = time.monotonic() + 5
        while peercred.is_alive(anchor) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not peercred.is_alive(anchor)
    finally:
        peercred.close_anchor(anchor)
