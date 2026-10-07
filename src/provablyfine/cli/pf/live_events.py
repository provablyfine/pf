"""A spool of session events, from the host to `pf bastion register`.

Whatever sees a session start or end on a host writes an event file here:
the PAM hook on Linux, the session reaper on macOS and Windows.
`pf bastion register` reads the files and reports them to the server.

Only root, or SYSTEM on Windows, can write to the directory.
The reader still checks every file.

A file stays until the server has accepted its event.
A file that is too old is removed, so the directory cannot grow without bound.
"""

from __future__ import annotations

import asyncio
import collections.abc
import dataclasses
import json
import logging
import os
import re
import stat
import time
import typing
import uuid

from ... import client

logger = logging.getLogger(__name__)

_CONNECTION_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SESSION_ID_RE = re.compile(r"[0-9A-Za-z._-]{0,64}")
_NAME_RE = re.compile(r"([0-9]{16})-(start|end)-[0-9a-f]{8}\.json")
MAX_EVENT_BYTES = 1024
# How long an event waits for the server, in seconds.
MAX_AGE = 600.0

EventKind = typing.Literal["start", "end"]


@dataclasses.dataclass(frozen=True)
class Event:
    kind: EventKind
    connection_id: str
    # The session on the host. Empty when there is none.
    session_id: str
    # When it happened, in seconds since the epoch.
    at: int


# The last time stamp this process used. Two events of one process never share one,
# so the file names sort in the order the events were written.
_last_us = 0


def _name(event: Event, now_us: int) -> str:
    global _last_us
    now_us = max(now_us, _last_us + 1)
    _last_us = now_us
    return f"{now_us:016d}-{event.kind}-{uuid.uuid4().hex[:8]}.json"


def write_event(directory: str, event: Event, *, now: typing.Callable[[], float] = time.time) -> str | None:
    """Write one event. Returns the path, or None when the event is not valid or could not be written."""
    if _CONNECTION_ID_RE.fullmatch(event.connection_id) is None or _SESSION_ID_RE.fullmatch(event.session_id) is None:
        logger.warning(f"live event has an unexpected format; it is dropped event={event!r}")
        return None
    path = os.path.join(directory, _name(event, int(now() * 1_000_000)))
    content = json.dumps(
        {"connection_id": event.connection_id, "session_id": event.session_id, "at": event.at}, sort_keys=True
    )
    try:
        client.configuration.write_file_atomic(path, content, mode="w", permissions=0o600)
    except OSError as e:
        logger.warning(f"cannot write live event; it is dropped path={path} error={e}")
        return None
    return path


def _read(path: str) -> Event | None:
    match = _NAME_RE.fullmatch(os.path.basename(path))
    if match is None:
        return None
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EVENT_BYTES:
        return None
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_EVENT_BYTES + 1)
        loaded: object = json.loads(data)
    except (OSError, ValueError):
        return None
    if not isinstance(loaded, dict):
        return None
    fields = typing.cast("dict[str, object]", loaded)
    connection_id = fields.get("connection_id")
    session_id = fields.get("session_id")
    at = fields.get("at")
    if not (isinstance(connection_id, str) and isinstance(session_id, str)):
        return None
    if not isinstance(at, int) or isinstance(at, bool) or at < 0:
        return None
    if _CONNECTION_ID_RE.fullmatch(connection_id) is None or _SESSION_ID_RE.fullmatch(session_id) is None:
        return None
    return Event(
        kind=typing.cast("EventKind", match.group(2)), connection_id=connection_id, session_id=session_id, at=at
    )


def read_events(directory: str) -> list[tuple[str, Event]]:
    """The valid events in the directory, oldest first."""
    try:
        names = sorted(os.listdir(directory))
    except OSError as e:
        logger.warning(f"cannot read live events directory={directory} error={e}")
        return []
    events: list[tuple[str, Event]] = []
    for name in names:
        path = os.path.join(directory, name)
        event = _read(path)
        if event is not None:
            events.append((path, event))
    return events


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _expire(directory: str, now: float, max_age: float) -> None:
    """Remove files that have waited too long, valid or not."""
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        path = os.path.join(directory, name)
        try:
            info = os.lstat(path)
        except OSError:
            continue
        if now - info.st_mtime > max_age:
            logger.info(f"dropping old live event path={path}")
            _remove(path)


async def forward(
    directory: str,
    send: collections.abc.Callable[[Event], collections.abc.Awaitable[None]],
    *,
    now: typing.Callable[[], float] = time.time,
    max_age: float = MAX_AGE,
) -> int:
    """Send every event, oldest first, and remove the ones that were accepted. Returns how many were sent.

    When an event fails, the later events of the same session wait for the next pass.
    This keeps an end from arriving before its start.
    Other sessions go on.
    """
    sent = 0
    blocked: set[tuple[str, str]] = set()
    for path, event in read_events(directory):
        session = (event.connection_id, event.session_id)
        if session in blocked:
            continue
        try:
            await send(event)
        except Exception as e:
            logger.warning(f"cannot report live event; it will be tried again path={path} error={e}")
            blocked.add(session)
            continue
        _remove(path)
        sent += 1
    _expire(directory, now(), max_age)
    return sent


async def run(
    directory: str,
    send: collections.abc.Callable[[Event], collections.abc.Awaitable[None]],
    *,
    interval: float = 1.0,
) -> None:
    """Forward the events of `directory` until cancelled."""
    logger.info(f"live events started directory={directory}")
    while True:
        try:
            await forward(directory, send)
        except Exception:
            logger.exception("live events pass failed")
        await asyncio.sleep(interval)
