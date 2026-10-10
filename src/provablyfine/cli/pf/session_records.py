"""The sessions that a Linux host has open, as seen by the PAM hook.

The PAM hook runs as root when a session opens.
It leaves one empty file per session, named `<connection id>-<logind session id>`.
The session reaper reads the names to turn a connection id into logind session ids.

The directory is in `/run`, so a reboot clears it.
A session id that logind hands out again after a reboot can never match an old file.
"""

from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

CONNECTION_ID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
# logind session ids are letters and digits, like "42" or "c3".
SESSION_ID = r"[A-Za-z0-9]{1,32}"
_CONNECTION_ID_RE = re.compile(CONNECTION_ID)
_SESSION_ID_RE = re.compile(SESSION_ID)
_NAME_RE = re.compile(rf"({CONNECTION_ID})-({SESSION_ID})")


def record_name(connection_id: str, session_id: str) -> str:
    return f"{connection_id}-{session_id}"


def write(directory: str, connection_id: str, session_id: str) -> bool:
    """Record an open session. Returns False when the ids are invalid or the file cannot be written."""
    if _CONNECTION_ID_RE.fullmatch(connection_id) is None or _SESSION_ID_RE.fullmatch(session_id) is None:
        logger.warning(f"unexpected session ids; the session cannot be ended on request id={connection_id!r}")
        return False
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(directory, record_name(connection_id, session_id)), os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
    except OSError:
        logger.warning("could not record the session", exc_info=True)
        return False
    return True


def remove(directory: str, connection_id: str, session_id: str) -> None:
    try:
        os.unlink(os.path.join(directory, record_name(connection_id, session_id)))
    except OSError:
        pass


def session_ids(directory: str, connection_id: str) -> list[str]:
    """The logind session ids recorded for this connection."""
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    found: list[str] = []
    for name in sorted(names):
        match = _NAME_RE.fullmatch(name)
        if match is not None and match.group(1) == connection_id:
            found.append(match.group(2))
    return found
