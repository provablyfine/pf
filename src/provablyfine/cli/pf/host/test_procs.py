from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from . import procs

PS_OUTPUT = """\
    1     0 /sbin/launchd
  100     1 sshd-session: alice [priv]
  101   100 sshd-session: alice@notty
  102   101 sleep 300
  200     1 sshd-session: bob [priv]
  300     1 /usr/sbin/cfprefsd agent
"""


def test_parse_ps_reads_pids_parents_and_commands() -> None:
    table = procs.parse_ps(PS_OUTPUT)
    assert table[100] == procs.Proc(100, 1, "sshd-session: alice [priv]")
    assert table[102].command == "sleep 300"
    assert len(table) == 6


def test_parse_ps_skips_lines_it_cannot_read() -> None:
    table = procs.parse_ps("garbage\n  12  1 ok\n  x  y z\n\n  13 12\n")
    assert sorted(table) == [12, 13]
    assert table[13].command == ""


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("sshd-session: alice [priv]", True),
        ("sshd: alice [priv]", True),
        ("sshd-session: alice@notty", False),
        ("sshd-auth: alice [net]", False),
        ("sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", False),
        ("vim sshd-session: alice [priv]", False),
        ("sshd-session: alice [priv] extra", False),
        ("sleep 300", False),
    ],
)
def test_is_sshd_monitor(command: str, expected: bool) -> None:
    assert procs.is_sshd_monitor(procs.Proc(10, 1, command)) is expected


def test_ancestors_are_listed_nearest_first() -> None:
    table = procs.parse_ps(PS_OUTPUT)
    assert [p.pid for p in procs.ancestors(table, 102)] == [101, 100, 1]
    assert procs.ancestors(table, 1) == []
    assert procs.ancestors(table, 9999) == []


def test_ancestors_stop_at_a_loop() -> None:
    table = procs.parse_ps("  5  6 a\n  6  5 b\n")
    assert [p.pid for p in procs.ancestors(table, 5)] == [6]


def test_find_ancestor_returns_the_nearest_match() -> None:
    table = procs.parse_ps(PS_OUTPUT)
    found = procs.find_ancestor(table, 102, procs.macos_connection)
    assert found is not None
    assert found.pid == 100
    assert procs.find_ancestor(table, 300, procs.macos_connection) is None


def test_descendants_lists_the_whole_subtree() -> None:
    table = procs.parse_ps(PS_OUTPUT)
    assert procs.descendants(table, 100) == [101, 102]
    assert procs.descendants(table, 200) == []
    assert procs.descendants(table, 1) == [100, 200, 300, 101, 102]


def test_descendants_do_not_include_the_process_itself_in_a_loop() -> None:
    table = procs.parse_ps("  5  6 a\n  6  5 b\n")
    assert procs.descendants(table, 5) == [6]


def test_parse_start_time() -> None:
    expected = int(time.mktime(time.strptime("2026 Oct 6 17:52:00", "%Y %b %d %H:%M:%S")))
    assert procs.parse_start_time("Tue Oct  6 17:52:00 2026") == expected
    assert procs.parse_start_time("  Tue Oct  6 17:52:00 2026\n") == expected
    assert procs.parse_start_time("") is None
    assert procs.parse_start_time("not a date") is None


@pytest.mark.skipif(sys.platform == "win32", reason="needs ps")
class TestPsTable:
    def test_snapshot_contains_this_process_and_its_parent(self) -> None:
        table = procs.PsTable().snapshot()
        assert table[os.getpid()].ppid == os.getppid()
        assert os.getppid() in table

    def test_snapshot_follows_a_child_we_start(self) -> None:
        child = subprocess.Popen(["sleep", "30"])  # noqa: S607
        try:
            table = procs.PsTable().snapshot()
            assert table[child.pid].ppid == os.getpid()
            assert table[child.pid].command.startswith("sleep")
            assert child.pid in procs.descendants(table, os.getpid())
        finally:
            child.kill()
            child.wait()

    def test_start_time_is_recent_for_a_new_process_and_missing_for_a_dead_one(self) -> None:
        child = subprocess.Popen(["sleep", "30"])  # noqa: S607
        started = procs.PsTable().start_time(child.pid)
        child.kill()
        child.wait()
        assert started is not None
        assert abs(started - time.time()) < 5
        assert procs.PsTable().start_time(child.pid) is None

    def test_send_signal_ignores_a_process_that_is_gone(self) -> None:
        child = subprocess.Popen(["true"])  # noqa: S607
        child.wait()
        procs.PsTable().send_signal(child.pid, force=False)


WINDOWS_TABLE = procs.parse_ps(
    """\
  500     4 services.exe
 3000   500 sshd.exe
 3100  3000 sshd.exe
 3200  3100 sshd.exe
 3300  3200 cmd.exe
 4000   500 notepad.exe
 5000  4000 sshd.exe
"""
)


def test_windows_connection_is_the_sshd_below_the_service() -> None:
    # 3000 is the service, 3100 the connection, 3200 the session.
    assert [pid for pid, proc in WINDOWS_TABLE.items() if procs.windows_connection(WINDOWS_TABLE, proc)] == [3100]


def test_windows_connection_ignores_case_and_other_programs() -> None:
    table = procs.parse_ps("  1  0 SERVICES.EXE\n  2  1 SSHD.EXE\n  3  2 Sshd.exe\n  4  3 cmd.exe\n")
    assert procs.windows_connection(table, table[3])
    assert not procs.windows_connection(table, table[4])
    assert not procs.windows_connection(table, table[2])


def test_windows_connection_needs_services_exe_two_levels_up() -> None:
    # An sshd.exe someone started by hand has no services.exe above it.
    assert not procs.windows_connection(WINDOWS_TABLE, WINDOWS_TABLE[5000])
    table = procs.parse_ps("  1  0 explorer.exe\n  2  1 sshd.exe\n  3  2 sshd.exe\n")
    assert not procs.windows_connection(table, table[3])


def test_find_ancestor_finds_the_windows_connection_from_the_command_below_it() -> None:
    table = dict(WINDOWS_TABLE)
    table[6000] = procs.Proc(6000, 3100, "pf.exe")
    found = procs.find_ancestor(table, 6000, procs.windows_connection)
    assert found is not None
    assert found.pid == 3100


def test_the_connection_test_matches_the_platform() -> None:
    expected = procs.windows_connection if sys.platform == "win32" else procs.macos_connection
    assert procs.connection_test() is expected
