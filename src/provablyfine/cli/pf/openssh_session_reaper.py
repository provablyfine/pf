"""End SSH sessions when the deadline in their certificate passes.

Linux does this with a PAM hook (`openssh_session_deadline.py`). macOS has no
`pam_exec`, so the work is split in two:

- `auth-principals` registers the connection when sshd asks it about a
  certificate. It runs as an unprivileged user, so it only writes a record.
- `pf openssh session-reaper` runs as root, reads the records and ends the
  sessions.

The records are written by an unprivileged user. The reaper treats them as
untrusted input and checks every process before it signals it.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import re
import signal
import stat
import sys
import time
import types
import typing

import provablyfine_client as pfc

from ... import client
from . import host

logger = logging.getLogger(__name__)

_CONNECTION_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_CONNECTION_ID_RE = re.compile(_CONNECTION_ID)
_RECORD_NAME_RE = re.compile(rf"([0-9]+)-({_CONNECTION_ID})\.json")
MAX_RECORD_BYTES = 4096
_MAX_PID = 2**31


@dataclasses.dataclass(frozen=True)
class Record:
    """One connection that has a deadline."""

    # The per-connection sshd process that runs as root.
    pid: int
    # When the record was written, in milliseconds since the epoch.
    written_ms: int
    # When the session must end, in seconds since the epoch.
    deadline: int
    connection_id: str


def record_name(pid: int, connection_id: str) -> str:
    return f"{pid}-{connection_id}.json"


def write_record(directory: str, record: Record) -> str:
    path = os.path.join(directory, record_name(record.pid, record.connection_id))
    content = json.dumps(
        {
            "pid": record.pid,
            "written_ms": record.written_ms,
            "deadline": record.deadline,
            "connection_id": record.connection_id,
        }
    )
    client.configuration.write_file_atomic(path, content, mode="w", permissions=0o600)
    return path


def _is_int(value: object) -> typing.TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def read_record(path: str) -> Record | None:
    """Read a record file, or return None when it is not a valid record.

    The directory belongs to an unprivileged user, so the file may be a
    symbolic link, a pipe or something huge.
    """
    match = _RECORD_NAME_RE.fullmatch(os.path.basename(path))
    if match is None:
        return None
    try:
        info = os.lstat(path)
    except OSError:
        return None
    # lstat does not follow links, so a symbolic link or a pipe is not a regular file here.
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RECORD_BYTES:
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        # The file may have been replaced between the two calls.
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_RECORD_BYTES:
            return None
        data = os.read(fd, MAX_RECORD_BYTES + 1)
    finally:
        os.close(fd)
    try:
        loaded: object = json.loads(data)
    except ValueError:
        return None
    if not isinstance(loaded, dict):
        return None
    fields = typing.cast("dict[str, object]", loaded)
    pid = fields.get("pid")
    written_ms = fields.get("written_ms")
    deadline = fields.get("deadline")
    connection_id = fields.get("connection_id")
    if not (_is_int(pid) and _is_int(written_ms) and _is_int(deadline) and isinstance(connection_id, str)):
        return None
    if not 1 < pid < _MAX_PID or written_ms <= 0 or deadline <= 0:
        return None
    if _CONNECTION_ID_RE.fullmatch(connection_id) is None:
        return None
    if (str(pid), connection_id) != match.groups():
        return None
    return Record(pid=pid, written_ms=written_ms, deadline=deadline, connection_id=connection_id)


def register_session(
    directory: str,
    *,
    deadline: int,
    connection_id: str,
    table: host.procs.ProcessTable,
    pid: int | None = None,
    now: typing.Callable[[], float] = time.time,
    is_connection: host.procs.ConnectionTest | None = None,
) -> str | None:
    """Record that the connection above `pid` must end at `deadline`.

    Returns the record path, or None when it could not be written.
    """
    if _CONNECTION_ID_RE.fullmatch(connection_id) is None:
        logger.warning(
            f"connection id has an unexpected format; the session deadline will not be enforced id={connection_id!r}"
        )
        return None
    pid = os.getpid() if pid is None else pid
    monitor = host.procs.find_ancestor(table.snapshot(), pid, is_connection or host.procs.connection_test())
    if monitor is None:
        logger.warning(f"no sshd connection process above pid={pid}; the session deadline will not be enforced")
        return None
    record = Record(pid=monitor.pid, written_ms=int(now() * 1000), deadline=deadline, connection_id=connection_id)
    return write_record(directory, record)


class Reaper:
    def __init__(
        self,
        directory: str,
        table: host.procs.ProcessTable,
        *,
        is_connection: host.procs.ConnectionTest | None = None,
        now: typing.Callable[[], float] = time.time,
        grace: float = 5.0,
    ) -> None:
        self._directory = directory
        self._table = table
        self._is_connection = is_connection or host.procs.connection_test()
        self._now = now
        self._grace = grace
        # Start time of the process each record was first matched with.
        self._bound: dict[str, int] = {}
        # When each session was first asked to end.
        self._ending: dict[str, float] = {}
        self._stopping = False

    def tick(self) -> None:
        try:
            names = sorted(os.listdir(self._directory))
        except FileNotFoundError:
            return
        snapshot = self._table.snapshot()
        present = set(names)
        for name in names:
            if _RECORD_NAME_RE.fullmatch(name) is None:
                continue
            try:
                self._handle(name, snapshot)
            except Exception:
                logger.warning(f"failed to handle record name={name}", exc_info=True)
        for name in [n for n in self._bound if n not in present]:
            self._forget(name)

    def _forget(self, name: str) -> None:
        self._bound.pop(name, None)
        self._ending.pop(name, None)

    def _drop(self, name: str, reason: str) -> None:
        logger.info(f"dropping record name={name} reason={reason}")
        try:
            os.unlink(os.path.join(self._directory, name))
        except FileNotFoundError:
            pass
        self._forget(name)

    def _handle(self, name: str, snapshot: host.procs.Snapshot) -> None:
        record = read_record(os.path.join(self._directory, name))
        if record is None:
            self._drop(name, "invalid record")
            return
        proc = snapshot.get(record.pid)
        started = self._table.start_time(record.pid) if proc is not None else None
        if proc is None or started is None:
            self._drop(name, "the session has ended")
            return
        bound = self._bound.get(name)
        if bound is None:
            if not self._is_connection(snapshot, proc):
                self._drop(name, f"pid {record.pid} is not an sshd connection process")
                return
            if started > record.written_ms // 1000:
                self._drop(name, f"pid {record.pid} started after the record was written")
                return
            self._bound[name] = started
        elif bound != started:
            self._drop(name, f"pid {record.pid} was reused")
            return
        self._enforce(name, record, snapshot)

    def _enforce(self, name: str, record: Record, snapshot: host.procs.Snapshot) -> None:
        now = self._now()
        ended_at = self._ending.get(name)
        if ended_at is None:
            if now < record.deadline:
                return
            logger.info(f"deadline reached, ending session connection_id={record.connection_id} pid={record.pid}")
            self._signal([*host.procs.descendants(snapshot, record.pid), record.pid], force=False)
            self._ending[name] = now
            return
        if now - ended_at >= self._grace:
            logger.info(
                f"session did not end in time, killing it connection_id={record.connection_id} pid={record.pid}"
            )
            self._signal([*host.procs.descendants(snapshot, record.pid), record.pid], force=True)

    def _signal(self, pids: typing.Iterable[int], *, force: bool) -> None:
        """Signal each process. A process that refuses must not stop the others from being signaled."""
        for pid in pids:
            try:
                self._table.send_signal(pid, force=force)
            except Exception:
                logger.warning(f"could not signal pid={pid} force={force}", exc_info=True)

    def _request_stop(self, signum: int, frame: types.FrameType | None) -> None:
        self._stopping = True

    def run(self, interval: float) -> None:
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)
        logger.info(f"session reaper started directory={self._directory}")
        while not self._stopping:
            self.tick()
            time.sleep(interval)
        logger.info("session reaper stopped")


def _directory_problem(directory: str) -> str | None:
    try:
        info = os.lstat(directory)
    except OSError as e:
        return f"cannot use {directory}: {e.strerror}"
    if not stat.S_ISDIR(info.st_mode):
        return f"{directory} is not a directory"
    # Windows has no mode bits. The directory's access list is set when it is created.
    if sys.platform != "win32" and info.st_mode & 0o022:
        return f"{directory} can be written by its group or by others"
    return None


def session_reaper_function(args: argparse.Namespace) -> None:
    """End SSH sessions at their certificate deadline. Must run as root."""
    if not host.is_privileged():
        raise pfc.exceptions.UI("session-reaper must run as root, or as an administrator on Windows")
    problem = _directory_problem(args.deadline_dir)
    if problem is not None:
        raise pfc.exceptions.UI(problem)
    Reaper(args.deadline_dir, host.procs.default_table(), grace=args.grace).run(args.interval)
