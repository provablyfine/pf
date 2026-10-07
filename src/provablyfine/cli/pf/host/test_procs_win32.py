from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time
import typing

import pytest

from .. import openssh_session_reaper
from . import procs

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="needs Windows")

CONNECTION_ID = "6f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b"


def _table() -> procs.ProcessTable:
    return procs.default_table()


def _wait_until(condition: typing.Callable[[], bool], seconds: float = 15.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.1)
    return condition()


class _Tree:
    """cmd.exe running a long ping: the ping stands in for a session, cmd.exe for the connection process."""

    def __init__(self) -> None:
        self.shell = subprocess.Popen(
            ["cmd.exe", "/c", "ping -n 300 127.0.0.1 > nul"],  # noqa: S607
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        assert _wait_until(lambda: bool(procs.descendants(_table().snapshot(), self.shell.pid)))
        self.children = procs.descendants(_table().snapshot(), self.shell.pid)

    def alive(self, pid: int) -> bool:
        return pid in _table().snapshot()

    def stop(self) -> None:
        for pid in self.children:
            try:
                _table().send_signal(pid, force=True)
            except OSError:
                pass
        self.shell.kill()
        self.shell.wait()


def test_the_snapshot_contains_this_process_and_its_parent_with_their_executable_names() -> None:
    snapshot = _table().snapshot()
    me = snapshot[os.getpid()]
    assert me.ppid == os.getppid()
    assert me.command.lower().endswith(".exe")
    assert os.getppid() in snapshot


def test_the_snapshot_follows_a_child_we_start() -> None:
    child = subprocess.Popen(["ping", "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)  # noqa: S607
    try:
        snapshot = _table().snapshot()
        assert snapshot[child.pid].ppid == os.getpid()
        assert snapshot[child.pid].command.lower() == "ping.exe"
        assert child.pid in procs.descendants(snapshot, os.getpid())
    finally:
        child.kill()
        child.wait()


def test_start_time_is_recent_for_a_new_process_and_a_dead_one_is_not_listed() -> None:
    child = subprocess.Popen(["ping", "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)  # noqa: S607
    started = _table().start_time(child.pid)
    child.kill()
    child.wait()
    assert started is not None
    assert abs(started - time.time()) < 10
    # The process may still be open for another process that holds a handle to it, but it is no longer listed.
    assert _wait_until(lambda: child.pid not in _table().snapshot())


def test_start_time_of_this_process_is_before_now() -> None:
    started = _table().start_time(os.getpid())
    assert started is not None
    assert started <= time.time()


def test_send_signal_ends_a_process_and_ignores_one_that_is_gone() -> None:
    child = subprocess.Popen(["ping", "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)  # noqa: S607
    _table().send_signal(child.pid, force=False)
    assert child.wait(timeout=10) is not None
    _table().send_signal(child.pid, force=True)


def test_the_connection_test_is_the_windows_one() -> None:
    assert procs.connection_test() is procs.windows_connection


def test_this_test_process_is_not_an_sshd_connection() -> None:
    snapshot = _table().snapshot()
    assert not procs.windows_connection(snapshot, snapshot[os.getpid()])


def test_the_reaper_ends_a_real_process_tree_at_its_deadline(tmp_path: pathlib.Path) -> None:
    tree = _Tree()
    try:
        record = openssh_session_reaper.Record(
            pid=tree.shell.pid,
            written_ms=int(time.time() * 1000) + 1_000,
            deadline=1_000,
            connection_id=CONNECTION_ID,
        )
        path = pathlib.Path(openssh_session_reaper.write_record(str(tmp_path), record))
        clock = [999.0]
        reaper = openssh_session_reaper.Reaper(
            str(tmp_path),
            _table(),
            is_connection=lambda snapshot, proc: proc.pid == tree.shell.pid,
            now=lambda: clock[0],
        )
        reaper.tick()
        assert tree.alive(tree.shell.pid)
        assert path.exists()
        clock[0] = 1_000.0
        reaper.tick()
        assert _wait_until(lambda: not tree.alive(tree.shell.pid))
        assert _wait_until(lambda: not any(tree.alive(pid) for pid in tree.children))
        reaper.tick()
        assert not path.exists()
    finally:
        tree.stop()


def test_a_record_for_an_unrelated_process_leaves_that_process_alone(tmp_path: pathlib.Path) -> None:
    bystander = subprocess.Popen(["ping", "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL)  # noqa: S607
    try:
        record = openssh_session_reaper.Record(
            pid=bystander.pid,
            written_ms=int(time.time() * 1000) + 1_000,
            deadline=1,
            connection_id=CONNECTION_ID,
        )
        path = pathlib.Path(openssh_session_reaper.write_record(str(tmp_path), record))
        openssh_session_reaper.Reaper(str(tmp_path), _table(), now=lambda: 9_999.0).tick()
        assert bystander.poll() is None
        assert not path.exists()
    finally:
        bystander.kill()
        bystander.wait()
