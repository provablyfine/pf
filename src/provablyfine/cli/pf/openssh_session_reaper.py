"""End SSH sessions when the deadline in their certificate passes, or when asked to.

Linux does this with a PAM hook (`openssh_pam_session_deadline_linux.py`). macOS has no
`pam_exec`, so the work is split in two:

- `auth-principals` registers the connection when sshd asks it about a
  certificate. It runs as an unprivileged user, so it only writes a record.
- `pf openssh session-reaper` runs as root, reads the records and ends the
  sessions.

The records are written by an unprivileged user. The reaper treats them as
untrusted input and checks every process before it signals it.

A session can also be ended on request. The request is an empty file named
`kill-<connection id>` in a second directory. Only root can write there, so
the reaper trusts the name. The reaper still checks the process before it
signals it.
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
import subprocess
import sys
import time
import types
import typing

import provablyfine_client as pfc

from ... import client
from . import host, live_events, session_records

logger = logging.getLogger(__name__)

_CONNECTION_ID = session_records.CONNECTION_ID
_CONNECTION_ID_RE = re.compile(_CONNECTION_ID)
_RECORD_NAME_RE = re.compile(rf"([0-9]+)-({_CONNECTION_ID})\.json")
_KILL_NAME_RE = re.compile(rf"kill-({_CONNECTION_ID})")
# How long a request waits for its session before it is removed, in seconds.
KILL_REQUEST_TTL = 60.0
MAX_RECORD_BYTES = 4096
_MAX_PID = 2**31


@dataclasses.dataclass(frozen=True)
class Record:
    """One connection, with the deadline it must end at if it has one."""

    # The per-connection sshd process that runs as root.
    pid: int
    # When the record was written, in milliseconds since the epoch.
    written_ms: int
    # When the session must end, in seconds since the epoch. None means no deadline.
    deadline: int | None
    connection_id: str


def record_name(pid: int, connection_id: str) -> str:
    return f"{pid}-{connection_id}.json"


def kill_request_name(connection_id: str) -> str:
    return f"kill-{connection_id}"


def request_kill(directory: str, connection_id: str) -> bool:
    """Ask the reaper to end the session of this connection.

    Returns False when the connection id is not valid or the request could not be written.
    """
    if _CONNECTION_ID_RE.fullmatch(connection_id) is None:
        logger.warning(f"connection id has an unexpected format; no kill request written id={connection_id!r}")
        return False
    try:
        client.configuration.write_file_atomic(
            os.path.join(directory, kill_request_name(connection_id)), "", mode="w", permissions=0o600
        )
    except OSError:
        logger.warning(f"could not write the kill request connection_id={connection_id}", exc_info=True)
        return False
    return True


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
    deadline = fields.get("deadline", False)
    connection_id = fields.get("connection_id")
    if deadline is not None and not _is_int(deadline):
        return None
    if not (_is_int(pid) and _is_int(written_ms) and isinstance(connection_id, str)):
        return None
    if not 1 < pid < _MAX_PID or written_ms <= 0 or (deadline is not None and deadline <= 0):
        return None
    if _CONNECTION_ID_RE.fullmatch(connection_id) is None:
        return None
    if (str(pid), connection_id) != match.groups():
        return None
    return Record(pid=pid, written_ms=written_ms, deadline=deadline, connection_id=connection_id)


def register_session(
    directory: str,
    *,
    deadline: int | None,
    connection_id: str,
    table: host.procs.ProcessTable,
    pid: int | None = None,
    now: typing.Callable[[], float] = time.time,
    is_connection: host.procs.ConnectionTest | None = None,
) -> str | None:
    """Record the connection above `pid`, and the `deadline` it must end at if it has one.

    Returns the record path, or None when it could not be written.
    """
    if _CONNECTION_ID_RE.fullmatch(connection_id) is None:
        logger.warning(f"connection id has an unexpected format; the session will not be tracked id={connection_id!r}")
        return None
    pid = os.getpid() if pid is None else pid
    monitor = host.procs.find_ancestor(table.snapshot(), pid, is_connection or host.procs.connection_test())
    if monitor is None:
        logger.warning(f"no sshd connection process above pid={pid}; the session will not be tracked")
        return None
    record = Record(pid=monitor.pid, written_ms=int(now() * 1000), deadline=deadline, connection_id=connection_id)
    return write_record(directory, record)


class KillRequests:
    """The requests to end a session, left by `request_kill` in a directory that only root can write."""

    def __init__(self, directory: str | None, now: typing.Callable[[], float] = time.time) -> None:
        self._directory = directory
        self._now = now
        # When each request was first seen without a live session.
        self._orphans: dict[str, float] = {}

    def requested(self) -> set[str]:
        """The connection ids that someone asked to end."""
        if self._directory is None:
            return set()
        try:
            names = os.listdir(self._directory)
        except OSError:
            return set()
        matches = (_KILL_NAME_RE.fullmatch(name) for name in names)
        return {m.group(1) for m in matches if m is not None}

    def remove(self, connection_id: str) -> None:
        if self._directory is None:
            return
        try:
            os.unlink(os.path.join(self._directory, kill_request_name(connection_id)))
        except FileNotFoundError:
            pass

    def expire(self, orphans: set[str]) -> None:
        """Remove the requests that no live session claims after a while."""
        if self._directory is None:
            return
        now = self._now()
        for connection_id in [c for c in self._orphans if c not in orphans]:
            del self._orphans[connection_id]
        for connection_id in orphans:
            first_seen = self._orphans.setdefault(connection_id, now)
            if now - first_seen < KILL_REQUEST_TTL:
                continue
            logger.info(f"dropping kill request connection_id={connection_id} reason=no session")
            self.remove(connection_id)
            del self._orphans[connection_id]


class Reaper:
    def __init__(
        self,
        directory: str,
        table: host.procs.ProcessTable,
        *,
        kill_directory: str | None = None,
        live_directory: str | None = None,
        is_connection: host.procs.ConnectionTest | None = None,
        now: typing.Callable[[], float] = time.time,
        grace: float = 5.0,
    ) -> None:
        self._directory = directory
        self._requests = KillRequests(kill_directory, now)
        self._live_directory = live_directory
        self._table = table
        self._is_connection = is_connection or host.procs.connection_test()
        self._now = now
        self._grace = grace
        # Start time of the process each record was first matched with.
        self._bound: dict[str, int] = {}
        # When each session was first asked to end.
        self._ending: dict[str, float] = {}
        # The records whose start was reported, so that their end is reported once.
        self._reported: dict[str, Record] = {}
        self._stopping = False

    def tick(self) -> None:
        try:
            names = sorted(os.listdir(self._directory))
        except FileNotFoundError:
            return
        snapshot = self._table.snapshot()
        present = set(names)
        requested = self._requests.requested()
        live: set[str] = set()
        for name in names:
            if _RECORD_NAME_RE.fullmatch(name) is None:
                continue
            try:
                record = self._handle(name, snapshot, requested)
            except Exception:
                logger.warning(f"failed to handle record name={name}", exc_info=True)
                continue
            if record is not None:
                live.add(record.connection_id)
        for name in [n for n in self._bound if n not in present]:
            self._forget(name)
        self._requests.expire(requested - live)

    def _forget(self, name: str) -> None:
        self._bound.pop(name, None)
        self._ending.pop(name, None)
        record = self._reported.pop(name, None)
        if record is not None:
            self._report("end", record, at=int(self._now()))

    def _report(self, kind: live_events.EventKind, record: Record, *, at: int) -> None:
        """Leave an event for `pf bastion register`. The session id is the connection process."""
        if self._live_directory is None:
            return
        event = live_events.Event(kind=kind, connection_id=record.connection_id, session_id=str(record.pid), at=at)
        live_events.write_event(self._live_directory, event, now=self._now)

    def _drop(self, name: str, reason: str) -> None:
        logger.info(f"dropping record name={name} reason={reason}")
        try:
            os.unlink(os.path.join(self._directory, name))
        except FileNotFoundError:
            pass
        self._forget(name)

    def _handle(self, name: str, snapshot: host.procs.Snapshot, requested: set[str]) -> Record | None:
        """Check one record and enforce it. Returns the record when its session is live."""
        record = read_record(os.path.join(self._directory, name))
        if record is None:
            self._drop(name, "invalid record")
            return None
        proc = snapshot.get(record.pid)
        started = self._table.start_time(record.pid) if proc is not None else None
        if proc is None or started is None:
            self._drop(name, "the session has ended")
            return None
        bound = self._bound.get(name)
        if bound is None:
            if not self._is_connection(snapshot, proc):
                self._drop(name, f"pid {record.pid} is not an sshd connection process")
                return None
            if started > record.written_ms // 1000:
                self._drop(name, f"pid {record.pid} started after the record was written")
                return None
            self._bound[name] = started
        elif bound != started:
            self._drop(name, f"pid {record.pid} was reused")
            return None
        if name not in self._reported:
            self._reported[name] = record
            self._report("start", record, at=record.written_ms // 1000)
        self._enforce(name, record, snapshot, kill_requested=record.connection_id in requested)
        return record

    def _enforce(self, name: str, record: Record, snapshot: host.procs.Snapshot, *, kill_requested: bool) -> None:
        now = self._now()
        ended_at = self._ending.get(name)
        if ended_at is None:
            if kill_requested:
                logger.info(f"kill requested, ending session connection_id={record.connection_id} pid={record.pid}")
            elif record.deadline is not None and now >= record.deadline:
                logger.info(f"deadline reached, ending session connection_id={record.connection_id} pid={record.pid}")
            else:
                return
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


_LOGINCTL = "/usr/bin/loginctl"
_LOGINCTL_TIMEOUT_S = 10.0


def loginctl_terminate_session(session_id: str) -> bool:
    """Ask logind to end a session. Returns whether it did."""
    try:
        result = subprocess.run(  # noqa: S603
            [_LOGINCTL, "terminate-session", session_id],
            check=False,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=_LOGINCTL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        logger.warning(f"loginctl failed session_id={session_id}", exc_info=True)
        return False
    if result.returncode != 0:
        logger.warning(f"loginctl terminate-session failed session_id={session_id} stderr={result.stderr!r}")
        return False
    return True


class LogindReaper:
    """Ends Linux sessions on request.

    The PAM hook records each open session in `sessions_directory`.
    A request names a connection id. The records turn it into logind session ids.
    A request that finds no session waits a while, because the session may still be starting.
    Deadlines are not handled here. The PAM hook sets a timer for them.
    """

    def __init__(
        self,
        kill_directory: str,
        sessions_directory: str,
        *,
        terminate: typing.Callable[[str], bool] = loginctl_terminate_session,
        now: typing.Callable[[], float] = time.time,
    ) -> None:
        self._requests = KillRequests(kill_directory, now)
        self._sessions_directory = sessions_directory
        self._terminate = terminate
        self._stopping = False

    def tick(self) -> None:
        requested = self._requests.requested()
        unclaimed: set[str] = set()
        for connection_id in sorted(requested):
            session_ids = session_records.session_ids(self._sessions_directory, connection_id)
            if not session_ids:
                unclaimed.add(connection_id)
                continue
            for session_id in session_ids:
                logger.info(f"kill requested, ending session connection_id={connection_id} session_id={session_id}")
                self._terminate(session_id)
            self._requests.remove(connection_id)
        self._requests.expire(unclaimed)

    def _request_stop(self, signum: int, frame: types.FrameType | None) -> None:
        self._stopping = True

    def run(self, interval: float) -> None:
        signal.signal(signal.SIGTERM, self._request_stop)
        signal.signal(signal.SIGINT, self._request_stop)
        logger.info("session reaper started")
        while not self._stopping:
            try:
                self.tick()
            except Exception:
                logger.warning("failed to handle kill requests", exc_info=True)
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
    """End SSH sessions at their certificate deadline, or when asked to. Must run as root."""
    if not host.is_privileged():
        raise pfc.exceptions.UI("session-reaper must run as root, or as an administrator on Windows")
    if args.sessions_dir is not None:
        if args.kill_dir is None:
            raise pfc.exceptions.UI("--sessions-dir needs --kill-dir")
        problem = _directory_problem(args.kill_dir)
        if problem is not None:
            raise pfc.exceptions.UI(problem)
        LogindReaper(args.kill_dir, args.sessions_dir).run(args.interval)
        return
    if args.deadline_dir is None:
        raise pfc.exceptions.UI("session-reaper needs --deadline-dir or --sessions-dir")
    problem = _directory_problem(args.deadline_dir)
    if problem is not None:
        raise pfc.exceptions.UI(problem)
    if args.kill_dir is not None:
        problem = _directory_problem(args.kill_dir)
        if problem is not None:
            raise pfc.exceptions.UI(problem)
    if args.live_dir is not None:
        problem = _directory_problem(args.live_dir)
        if problem is not None:
            raise pfc.exceptions.UI(problem)
    Reaper(
        args.deadline_dir,
        host.procs.default_table(),
        kill_directory=args.kill_dir,
        live_directory=args.live_dir,
        grace=args.grace,
    ).run(args.interval)
