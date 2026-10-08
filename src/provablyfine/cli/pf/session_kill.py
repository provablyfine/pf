"""End live sessions on request.

The bastion relay calls this when the server sends a signed command.
A session is either a tunnel that the relay carries, or a session that the host reports.

Tunnels are closed here.
Host sessions are ended by `loginctl` on Linux.
On macOS and Windows a request file goes to the session reaper.
"""

from __future__ import annotations

import asyncio
import collections.abc
import logging
import re
import sys
import time

from . import openssh_session_reaper

logger = logging.getLogger(__name__)

# systemd session ids are letters and digits, like "42" or "c3".
_LOGIND_SESSION_RE = re.compile(r"[A-Za-z0-9]{1,32}")
_LOGINCTL = "loginctl"
_LOGINCTL_TIMEOUT_S = 10.0
# The host registers a session a moment after logind starts it.
_START_SLACK_S = 10


class Terminator:
    """Ends the sessions of one host."""

    def __init__(self, kill_dir: str | None) -> None:
        self._kill_dir = kill_dir
        self._tunnels: dict[str, collections.abc.Callable[[], None]] = {}

    def track_tunnel(self, token_id: str, close: collections.abc.Callable[[], None]) -> None:
        self._tunnels[token_id] = close

    def untrack_tunnel(self, token_id: str) -> None:
        self._tunnels.pop(token_id, None)

    async def terminate(
        self, kind: str, connection_id: str, session_id: str, started_at: int | None = None
    ) -> str | None:
        """End a session. Return None on success, or the reason it could not be done."""
        if kind == "relay":
            close = self._tunnels.get(session_id)
            if close is None:
                return "no such tunnel"
            close()
            return None
        if kind == "host":
            return await self._terminate_host(connection_id, session_id, started_at)
        return "unknown kind"

    async def _terminate_host(self, connection_id: str, session_id: str, started_at: int | None) -> str | None:
        if sys.platform == "linux":
            return await _loginctl_terminate(session_id, started_at)
        if self._kill_dir is None:
            return "host sessions cannot be ended: no kill directory"
        if not openssh_session_reaper.request_kill(self._kill_dir, connection_id):
            return "kill request not written"
        return None


def session_started_at(monotonic_us: int, now: float, monotonic_now: float) -> float:
    """When a logind session began, in seconds since the epoch.

    logind reports the start as microseconds on the monotonic clock.

    That clock does not run while the host is suspended.
    After a suspend the result is too late, so the kill is refused.
    A refused kill is the safe mistake.
    """
    return now - (monotonic_now - monotonic_us / 1_000_000)


def is_a_later_session(logind_started_at: float, registered_started_at: int) -> bool:
    """Whether logind now holds another session under the id that the host registered.

    logind numbers sessions again after a reboot.
    A session that began after the registered one cannot be it.
    """
    return logind_started_at > registered_started_at + _START_SLACK_S


async def _run_loginctl(*args: str) -> tuple[int | None, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        _LOGINCTL,
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    async with asyncio.timeout(_LOGINCTL_TIMEOUT_S):
        stdout, stderr = await process.communicate()
    return process.returncode, stdout, stderr


async def _loginctl_terminate(session_id: str, started_at: int | None) -> str | None:
    if _LOGIND_SESSION_RE.fullmatch(session_id) is None:
        logger.warning(f"session id has an unexpected format; nothing ended id={session_id!r}")
        return "invalid session id"
    if started_at is None:
        return "the command does not say when the session started"
    try:
        code, stdout, stderr = await _run_loginctl(
            "show-session", session_id, "--property=TimestampMonotonic", "--value"
        )
        if code != 0 or not stdout.strip().isdigit():
            logger.warning(f"loginctl show-session failed session_id={session_id} stderr={stderr!r}")
            return "no such session"
        logind_started = session_started_at(int(stdout.strip()), time.time(), time.monotonic())
        if is_a_later_session(logind_started, started_at):
            logger.warning(f"session id now belongs to a later session; nothing ended session_id={session_id}")
            return "no such session"
        code, _, stderr = await _run_loginctl("terminate-session", session_id)
    except (OSError, TimeoutError):
        logger.warning(f"loginctl failed session_id={session_id}", exc_info=True)
        return "loginctl failed"
    if code != 0:
        logger.warning(f"loginctl terminate-session failed session_id={session_id} stderr={stderr!r}")
        return "loginctl failed"
    return None
