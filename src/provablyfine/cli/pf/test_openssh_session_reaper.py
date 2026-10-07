from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
import typing

import provablyfine_client as pfc
import psutil
import pytest

from . import host, live_events, openssh_session_reaper

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes, links or pipes")

CONNECTION_ID = "6f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b"
OTHER_CONNECTION_ID = "11111111-2222-4333-8444-555555555555"


class FakeTable:
    """A process table the tests can edit, that records the signals sent."""

    def __init__(self, procs: list[host.procs.Proc], started: dict[int, int]) -> None:
        self.procs = {p.pid: p for p in procs}
        self.started = dict(started)
        self.sent: list[tuple[int, bool]] = []

    def snapshot(self) -> host.procs.Snapshot:
        return dict(self.procs)

    def start_time(self, pid: int) -> int | None:
        return self.started.get(pid)

    def send_signal(self, pid: int, *, force: bool) -> None:
        self.sent.append((pid, force))
        if force:
            self.procs.pop(pid, None)


def _session_table() -> FakeTable:
    return FakeTable(
        [
            host.procs.Proc(1, 0, "launchd"),
            host.procs.Proc(100, 1, "sshd-session: alice [priv]"),
            host.procs.Proc(101, 100, "sshd-session: alice@notty"),
            host.procs.Proc(102, 101, "sleep 300"),
            host.procs.Proc(900, 1, "important-daemon"),
        ],
        {100: 1_000, 101: 1_001, 102: 1_002, 900: 500},
    )


def _record(**overrides: object) -> openssh_session_reaper.Record:
    fields: dict[str, object] = {
        "pid": 100,
        "written_ms": 1_000_500,
        "deadline": 5_000,
        "connection_id": CONNECTION_ID,
    }
    fields.update(overrides)
    return openssh_session_reaper.Record(**typing.cast("dict[str, typing.Any]", fields))


def _put(directory: pathlib.Path, record: openssh_session_reaper.Record) -> pathlib.Path:
    return pathlib.Path(openssh_session_reaper.write_record(str(directory), record))


def _monitor(snapshot: host.procs.Snapshot, proc: host.procs.Proc) -> bool:
    return host.procs.is_sshd_monitor(proc)


def _reaper(
    directory: pathlib.Path, table: FakeTable, clock: list[float], grace: float = 5.0
) -> openssh_session_reaper.Reaper:
    return openssh_session_reaper.Reaper(
        str(directory), table, is_connection=_monitor, now=lambda: clock[0], grace=grace
    )


def test_a_record_survives_a_round_trip(tmp_path: pathlib.Path) -> None:
    record = _record()
    path = _put(tmp_path, record)
    assert path.name == f"100-{CONNECTION_ID}.json"
    if sys.platform != "win32":
        assert path.stat().st_mode & 0o777 == 0o600
    assert openssh_session_reaper.read_record(str(path)) == record


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "[]",
        '"text"',
        "{}",
        json.dumps({"pid": 100, "written_ms": 1, "deadline": 1}),
        json.dumps({"pid": "100", "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": True, "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 100, "written_ms": 1.5, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 1, "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 0, "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": -5, "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 2**40, "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 100, "written_ms": 0, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 100, "written_ms": 1, "deadline": -1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 100, "written_ms": 1, "deadline": 1, "connection_id": "../../etc/passwd"}),
        # The name and the content must agree.
        json.dumps({"pid": 101, "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}),
        json.dumps({"pid": 100, "written_ms": 1, "deadline": 1, "connection_id": OTHER_CONNECTION_ID}),
        "x" * (openssh_session_reaper.MAX_RECORD_BYTES + 1),
    ],
)
def test_read_record_rejects_invalid_content(tmp_path: pathlib.Path, content: str) -> None:
    path = tmp_path / f"100-{CONNECTION_ID}.json"
    path.write_text(content)
    assert openssh_session_reaper.read_record(str(path)) is None


def test_read_record_rejects_other_file_names(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "anything.json"
    path.write_text(json.dumps({"pid": 100, "written_ms": 1, "deadline": 1, "connection_id": CONNECTION_ID}))
    assert openssh_session_reaper.read_record(str(path)) is None
    assert openssh_session_reaper.read_record(str(tmp_path / f"100-{CONNECTION_ID}.json")) is None


@posix_only
def test_read_record_does_not_follow_symbolic_links(tmp_path: pathlib.Path) -> None:
    real = _put(tmp_path, _record())
    link = tmp_path / f"200-{CONNECTION_ID}.json"
    link.symlink_to(real)
    assert openssh_session_reaper.read_record(str(link)) is None


@posix_only
def test_read_record_does_not_block_on_a_pipe(tmp_path: pathlib.Path) -> None:
    fifo = tmp_path / f"100-{CONNECTION_ID}.json"
    os.mkfifo(fifo)
    assert openssh_session_reaper.read_record(str(fifo)) is None


def test_register_session_records_the_connection_process_above_us(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    table.procs[4242] = host.procs.Proc(4242, 102, "pf openssh auth-principals")
    path = openssh_session_reaper.register_session(
        str(tmp_path),
        deadline=5_000,
        connection_id=CONNECTION_ID,
        table=table,
        pid=4242,
        now=lambda: 1_000.5,
        is_connection=_monitor,
    )
    assert path == str(tmp_path / f"100-{CONNECTION_ID}.json")
    assert openssh_session_reaper.read_record(str(path)) == _record(written_ms=1_000_500)


def test_register_session_writes_nothing_without_an_sshd_connection_above_us(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    table.procs[4242] = host.procs.Proc(4242, 900, "pf openssh auth-principals")
    assert (
        openssh_session_reaper.register_session(
            str(tmp_path), deadline=5_000, connection_id=CONNECTION_ID, table=table, pid=4242
        )
        is None
    )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("connection_id", ["", "short", "../x", CONNECTION_ID.upper(), CONNECTION_ID + "0"])
def test_register_session_refuses_an_unexpected_connection_id(tmp_path: pathlib.Path, connection_id: str) -> None:
    table = _session_table()
    table.procs[4242] = host.procs.Proc(4242, 102, "pf")
    assert (
        openssh_session_reaper.register_session(
            str(tmp_path), deadline=5_000, connection_id=connection_id, table=table, pid=4242
        )
        is None
    )
    assert list(tmp_path.iterdir()) == []


def test_nothing_happens_before_the_deadline(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    path = _put(tmp_path, _record())
    reaper = _reaper(tmp_path, table, [4_999.0])
    reaper.tick()
    reaper.tick()
    assert table.sent == []
    assert path.exists()


def test_at_the_deadline_descendants_are_terminated_before_the_connection_process(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    _put(tmp_path, _record())
    clock = [5_000.0]
    _reaper(tmp_path, table, clock).tick()
    assert table.sent == [(101, False), (102, False), (100, False)]


def test_a_session_that_does_not_end_is_killed_after_the_grace_period(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    _put(tmp_path, _record())
    clock = [5_000.0]
    reaper = _reaper(tmp_path, table, clock, grace=5.0)
    reaper.tick()
    table.sent.clear()
    clock[0] = 5_004.0
    reaper.tick()
    assert table.sent == []
    clock[0] = 5_005.0
    reaper.tick()
    assert sorted(table.sent) == [(100, True), (101, True), (102, True)]


def test_the_record_goes_away_once_the_session_has_ended(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    path = _put(tmp_path, _record())
    clock = [5_000.0]
    reaper = _reaper(tmp_path, table, clock)
    reaper.tick()
    for pid in (100, 101, 102):
        del table.procs[pid]
    reaper.tick()
    assert not path.exists()


def test_a_record_for_a_session_that_ended_before_its_deadline_is_dropped(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    path = _put(tmp_path, _record())
    for pid in (100, 101, 102):
        del table.procs[pid]
    _reaper(tmp_path, table, [10.0]).tick()
    assert not path.exists()
    assert table.sent == []


def test_a_record_that_points_at_an_unrelated_process_is_dropped_and_nothing_is_signaled(
    tmp_path: pathlib.Path,
) -> None:
    table = _session_table()
    path = _put(tmp_path, _record(pid=900))
    _reaper(tmp_path, table, [9_999.0]).tick()
    assert table.sent == []
    assert not path.exists()


def test_the_default_check_refuses_an_sshd_process_that_launchd_did_not_start(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    table.procs[100] = host.procs.Proc(100, 555, "sshd-session: alice [priv]")
    path = _put(tmp_path, _record())
    openssh_session_reaper.Reaper(str(tmp_path), table, now=lambda: 9_999.0).tick()
    assert table.sent == []
    assert not path.exists()


def test_a_process_that_started_after_the_record_was_written_is_not_signaled(tmp_path: pathlib.Path) -> None:
    # The pid was reused: the process that wrote the record is gone and a new one has its number.
    table = _session_table()
    table.started[100] = 2_000
    path = _put(tmp_path, _record(written_ms=1_500_000))
    _reaper(tmp_path, table, [9_999.0]).tick()
    assert table.sent == []
    assert not path.exists()


def test_a_process_that_starts_in_the_same_second_the_record_was_written_is_accepted(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    table.started[100] = 1_000
    _put(tmp_path, _record(written_ms=1_000_900))
    _reaper(tmp_path, table, [9_999.0]).tick()
    assert (100, False) in table.sent


def test_a_pid_that_is_reused_while_we_wait_is_not_signaled(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    path = _put(tmp_path, _record())
    clock = [100.0]
    reaper = _reaper(tmp_path, table, clock)
    reaper.tick()
    assert path.exists()
    table.started[100] = 1_900
    clock[0] = 9_999.0
    reaper.tick()
    assert table.sent == []
    assert not path.exists()


def test_invalid_and_unrelated_files_are_handled(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    bad = tmp_path / f"100-{CONNECTION_ID}.json"
    bad.write_text("not json")
    unrelated = tmp_path / "notes.txt"
    unrelated.write_text("keep me")
    _reaper(tmp_path, table, [9_999.0]).tick()
    assert not bad.exists()
    assert unrelated.exists()
    assert table.sent == []


def test_two_connections_are_handled_independently(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    table.procs[200] = host.procs.Proc(200, 1, "sshd-session: bob [priv]")
    table.started[200] = 1_000
    _put(tmp_path, _record(deadline=5_000))
    _put(tmp_path, _record(pid=200, deadline=9_000, connection_id=OTHER_CONNECTION_ID))
    _reaper(tmp_path, table, [6_000.0]).tick()
    assert (100, False) in table.sent
    assert (200, False) not in table.sent


def _killing_reaper(
    directory: pathlib.Path, kill_directory: pathlib.Path, table: FakeTable, clock: list[float]
) -> openssh_session_reaper.Reaper:
    return openssh_session_reaper.Reaper(
        str(directory), table, kill_directory=str(kill_directory), is_connection=_monitor, now=lambda: clock[0]
    )


def _kill_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "kill"
    path.mkdir()
    return path


def test_a_record_without_a_deadline_round_trips(tmp_path: pathlib.Path) -> None:
    record = _record(deadline=None)
    assert openssh_session_reaper.read_record(str(_put(tmp_path, record))) == record


def test_a_record_without_a_deadline_field_is_rejected(tmp_path: pathlib.Path) -> None:
    path = tmp_path / f"100-{CONNECTION_ID}.json"
    path.write_text(json.dumps({"pid": 100, "written_ms": 1, "connection_id": CONNECTION_ID}))
    assert openssh_session_reaper.read_record(str(path)) is None


@pytest.mark.parametrize("deadline", [True, 0, -1, 1.5, "5"])
def test_read_record_rejects_an_invalid_deadline(tmp_path: pathlib.Path, deadline: object) -> None:
    path = tmp_path / f"100-{CONNECTION_ID}.json"
    path.write_text(json.dumps({"pid": 100, "written_ms": 1, "deadline": deadline, "connection_id": CONNECTION_ID}))
    assert openssh_session_reaper.read_record(str(path)) is None


def test_register_session_records_a_connection_without_a_deadline(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    table.procs[4242] = host.procs.Proc(4242, 102, "pf openssh auth-principals")
    path = openssh_session_reaper.register_session(
        str(tmp_path),
        deadline=None,
        connection_id=CONNECTION_ID,
        table=table,
        pid=4242,
        now=lambda: 1_000.5,
        is_connection=_monitor,
    )
    assert path is not None
    assert openssh_session_reaper.read_record(path) == _record(deadline=None, written_ms=1_000_500)


def test_a_session_without_a_deadline_is_never_ended_by_time(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    path = _put(tmp_path, _record(deadline=None))
    _reaper(tmp_path, table, [10.0**12]).tick()
    assert table.sent == []
    assert path.exists()


def test_a_kill_request_ends_a_session_before_its_deadline(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    kill = _kill_dir(tmp_path)
    _put(tmp_path, _record(deadline=None))
    reaper = _killing_reaper(tmp_path, kill, table, [100.0])
    reaper.tick()
    assert table.sent == []
    assert openssh_session_reaper.request_kill(str(kill), CONNECTION_ID)
    reaper.tick()
    assert table.sent == [(101, False), (102, False), (100, False)]


def test_a_session_that_ignores_a_kill_request_is_killed_after_the_grace_period(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    kill = _kill_dir(tmp_path)
    _put(tmp_path, _record())
    clock = [100.0]
    reaper = _killing_reaper(tmp_path, kill, table, clock)
    openssh_session_reaper.request_kill(str(kill), CONNECTION_ID)
    reaper.tick()
    table.sent.clear()
    clock[0] = 105.0
    reaper.tick()
    assert sorted(table.sent) == [(100, True), (101, True), (102, True)]


def test_a_kill_request_only_ends_its_own_connection(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    table.procs[200] = host.procs.Proc(200, 1, "sshd-session: bob [priv]")
    table.started[200] = 1_000
    kill = _kill_dir(tmp_path)
    _put(tmp_path, _record(deadline=None))
    _put(tmp_path, _record(pid=200, deadline=None, connection_id=OTHER_CONNECTION_ID))
    openssh_session_reaper.request_kill(str(kill), OTHER_CONNECTION_ID)
    _killing_reaper(tmp_path, kill, table, [100.0]).tick()
    assert (200, False) in table.sent
    assert (100, False) not in table.sent


def test_a_kill_request_cannot_signal_a_process_that_is_not_an_sshd_connection(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    kill = _kill_dir(tmp_path)
    _put(tmp_path, _record(pid=900, deadline=None))
    openssh_session_reaper.request_kill(str(kill), CONNECTION_ID)
    _killing_reaper(tmp_path, kill, table, [100.0]).tick()
    assert table.sent == []


def test_a_kill_request_for_an_unknown_connection_is_removed_after_a_while(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    kill = _kill_dir(tmp_path)
    openssh_session_reaper.request_kill(str(kill), CONNECTION_ID)
    clock = [100.0]
    reaper = _killing_reaper(tmp_path, kill, table, clock)
    reaper.tick()
    clock[0] = 100.0 + openssh_session_reaper.KILL_REQUEST_TTL - 1
    reaper.tick()
    assert (kill / f"kill-{CONNECTION_ID}").exists()
    clock[0] = 100.0 + openssh_session_reaper.KILL_REQUEST_TTL
    reaper.tick()
    assert list(kill.iterdir()) == []
    assert table.sent == []


def test_a_kill_request_waits_for_a_record_that_appears_later(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    kill = _kill_dir(tmp_path)
    openssh_session_reaper.request_kill(str(kill), CONNECTION_ID)
    clock = [100.0]
    reaper = _killing_reaper(tmp_path, kill, table, clock)
    reaper.tick()
    _put(tmp_path, _record(deadline=None))
    clock[0] = 110.0
    reaper.tick()
    assert (100, False) in table.sent


def test_a_kill_request_for_a_live_session_is_kept(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    kill = _kill_dir(tmp_path)
    _put(tmp_path, _record(deadline=None))
    openssh_session_reaper.request_kill(str(kill), CONNECTION_ID)
    clock = [100.0]
    reaper = _killing_reaper(tmp_path, kill, table, clock)
    reaper.tick()
    clock[0] = 100.0 + 2 * openssh_session_reaper.KILL_REQUEST_TTL
    reaper.tick()
    assert (kill / f"kill-{CONNECTION_ID}").exists()


def test_files_in_the_kill_directory_with_other_names_are_ignored(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    kill = _kill_dir(tmp_path)
    _put(tmp_path, _record(deadline=None))
    for name in ("notes.txt", f"kill-{CONNECTION_ID}.json", CONNECTION_ID, f"kill-{CONNECTION_ID.upper()}"):
        (kill / name).write_text("")
    _killing_reaper(tmp_path, kill, table, [100.0]).tick()
    assert table.sent == []
    assert (kill / "notes.txt").exists()


@pytest.mark.parametrize("connection_id", ["", "short", "../x", CONNECTION_ID.upper(), CONNECTION_ID + "0"])
def test_request_kill_refuses_an_unexpected_connection_id(tmp_path: pathlib.Path, connection_id: str) -> None:
    assert not openssh_session_reaper.request_kill(str(tmp_path), connection_id)
    assert list(tmp_path.iterdir()) == []


def test_request_kill_reports_a_directory_it_cannot_write(tmp_path: pathlib.Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("")
    assert not openssh_session_reaper.request_kill(str(blocker / "sub"), CONNECTION_ID)


def test_a_missing_kill_directory_is_not_an_error(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    _put(tmp_path, _record(deadline=None))
    _killing_reaper(tmp_path, tmp_path / "missing", table, [100.0]).tick()
    assert table.sent == []


def test_a_missing_directory_is_not_an_error(tmp_path: pathlib.Path) -> None:
    _reaper(tmp_path / "missing", _session_table(), [0.0]).tick()


def _alive(pid: int) -> bool:
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def _wait_until(condition: typing.Callable[[], bool], seconds: float = 10.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


class _Tree:
    """A shell with two sleeping children, standing in for an sshd session."""

    def __init__(self, ignore_term: bool) -> None:
        trap = 'trap "" TERM; ' if ignore_term else ""
        self.shell = subprocess.Popen(  # noqa: S603
            ["sh", "-c", f"{trap}sleep 300 & sleep 300 & wait"],  # noqa: S607
            start_new_session=True,
        )
        assert _wait_until(lambda: len(psutil.Process(self.shell.pid).children()) == 2)
        self.children = [c.pid for c in psutil.Process(self.shell.pid).children()]

    def everyone_alive(self) -> bool:
        return all(_alive(pid) for pid in [self.shell.pid, *self.children])

    def stop(self) -> None:
        for pid in self.children:
            try:
                os.kill(pid, True)
            except ProcessLookupError:
                pass
        self.shell.kill()
        self.shell.wait()


def _reaper_for(tree: _Tree, directory: pathlib.Path, clock: list[float]) -> openssh_session_reaper.Reaper:
    return openssh_session_reaper.Reaper(
        str(directory),
        host.procs.PsTable(),
        is_connection=lambda snapshot, proc: proc.pid == tree.shell.pid,
        now=lambda: clock[0],
        grace=5.0,
    )


def _record_for(tree: _Tree) -> openssh_session_reaper.Record:
    return _record(pid=tree.shell.pid, written_ms=int(time.time() * 1000) + 1_000)


@posix_only
def test_the_reaper_ends_a_real_process_tree_with_sigterm(tmp_path: pathlib.Path) -> None:
    tree = _Tree(ignore_term=False)
    try:
        record = _record_for(tree)
        _put(tmp_path, record)
        clock = [float(record.deadline) - 1]
        reaper = _reaper_for(tree, tmp_path, clock)
        reaper.tick()
        assert tree.everyone_alive()
        clock[0] = float(record.deadline)
        reaper.tick()
        assert _wait_until(lambda: tree.shell.poll() is not None)
        assert _wait_until(lambda: not any(_alive(pid) for pid in tree.children))
    finally:
        tree.stop()


@posix_only
def test_the_reaper_kills_a_real_process_tree_that_ignores_sigterm(tmp_path: pathlib.Path) -> None:
    tree = _Tree(ignore_term=True)
    try:
        record = _record_for(tree)
        _put(tmp_path, record)
        clock = [float(record.deadline)]
        reaper = _reaper_for(tree, tmp_path, clock)
        reaper.tick()
        time.sleep(0.5)
        assert tree.everyone_alive(), "the processes ignore SIGTERM, so they must still be there"
        clock[0] = float(record.deadline) + 5
        reaper.tick()
        assert _wait_until(lambda: tree.shell.poll() is not None)
        assert _wait_until(lambda: not any(_alive(pid) for pid in tree.children))
    finally:
        tree.stop()


def test_the_reaper_command_refuses_to_run_unprivileged(tmp_path: pathlib.Path) -> None:
    if host.is_privileged():
        pytest.skip("running with privileges")
    args = typing.cast("typing.Any", type("Args", (), {"deadline_dir": str(tmp_path), "interval": 1.0, "grace": 5.0}))
    with pytest.raises(pfc.exceptions.UI, match="must run as root"):
        openssh_session_reaper.session_reaper_function(args)


@posix_only
def test_a_directory_that_others_can_write_is_refused(tmp_path: pathlib.Path) -> None:
    tmp_path.chmod(0o777)
    problem = openssh_session_reaper._directory_problem(str(tmp_path))
    assert problem is not None
    assert "written" in problem
    tmp_path.chmod(0o700)
    assert openssh_session_reaper._directory_problem(str(tmp_path)) is None
    assert openssh_session_reaper._directory_problem(str(tmp_path / "missing")) is not None


def _live_reaper(
    directory: pathlib.Path, live: pathlib.Path | None, table: FakeTable, clock: list[float]
) -> openssh_session_reaper.Reaper:
    return openssh_session_reaper.Reaper(
        str(directory),
        table,
        live_directory=None if live is None else str(live),
        is_connection=_monitor,
        now=lambda: clock[0],
    )


def _events(live: pathlib.Path) -> list[tuple[str, str, str]]:
    return [(e.kind, e.connection_id, e.session_id) for _, e in live_events.read_events(str(live))]


def test_a_session_is_reported_once_when_it_starts_and_once_when_it_ends(tmp_path: pathlib.Path) -> None:
    records, live = tmp_path / "records", tmp_path / "live"
    records.mkdir()
    live.mkdir()
    table = _session_table()
    _put(records, _record(deadline=None))
    reaper = _live_reaper(records, live, table, [2_000.0])

    reaper.tick()
    reaper.tick()
    assert _events(live) == [("start", CONNECTION_ID, "100")]

    for pid in (100, 101, 102):
        del table.procs[pid]
    reaper.tick()
    reaper.tick()
    assert _events(live) == [("start", CONNECTION_ID, "100"), ("end", CONNECTION_ID, "100")]


def test_the_start_is_dated_when_the_record_was_written(tmp_path: pathlib.Path) -> None:
    records, live = tmp_path / "records", tmp_path / "live"
    records.mkdir()
    live.mkdir()
    _put(records, _record(written_ms=1_000_500))

    _live_reaper(records, live, _session_table(), [2_000.0]).tick()

    [(_, event)] = live_events.read_events(str(live))
    assert event.at == 1_000


def test_a_session_killed_at_its_deadline_is_reported_as_ended(tmp_path: pathlib.Path) -> None:
    records, live = tmp_path / "records", tmp_path / "live"
    records.mkdir()
    live.mkdir()
    table = _session_table()
    _put(records, _record())
    clock = [5_000.0]
    reaper = _live_reaper(records, live, table, clock)

    reaper.tick()
    clock[0] = 5_010.0
    reaper.tick()
    reaper.tick()

    assert _events(live) == [("start", CONNECTION_ID, "100"), ("end", CONNECTION_ID, "100")]


def test_a_record_that_is_not_a_session_is_not_reported(tmp_path: pathlib.Path) -> None:
    records, live = tmp_path / "records", tmp_path / "live"
    records.mkdir()
    live.mkdir()
    _put(records, _record(pid=900))

    _live_reaper(records, live, _session_table(), [2_000.0]).tick()

    assert _events(live) == []


def test_nothing_is_reported_without_a_live_directory(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    _put(tmp_path, _record(deadline=None))

    _live_reaper(tmp_path, None, table, [2_000.0]).tick()

    assert [p.name for p in tmp_path.iterdir()] == [f"100-{CONNECTION_ID}.json"]


def test_a_live_directory_that_cannot_be_written_does_not_stop_the_reaper(tmp_path: pathlib.Path) -> None:
    table = _session_table()
    _put(tmp_path, _record())
    clock = [5_000.0]

    _live_reaper(tmp_path, tmp_path / "missing", table, clock).tick()

    assert table.sent == [(101, False), (102, False), (100, False)]
