"""End live sessions on request.

The bastion relay calls this when the server sends a signed command.
A session is either a tunnel that the relay carries, or a session that the host reports.

Tunnels are closed here.
Host sessions are ended by the session reaper, which runs with the rights to do it.
This process only leaves a request in a directory that the reaper reads.
"""

from __future__ import annotations

import collections.abc
import logging

from . import openssh_session_reaper

logger = logging.getLogger(__name__)


class Terminator:
    """Ends the sessions of one host."""

    def __init__(self, kill_dir: str | None) -> None:
        self._kill_dir = kill_dir
        self._tunnels: dict[str, collections.abc.Callable[[], None]] = {}

    def track_tunnel(self, token_id: str, close: collections.abc.Callable[[], None]) -> None:
        self._tunnels[token_id] = close

    def untrack_tunnel(self, token_id: str) -> None:
        self._tunnels.pop(token_id, None)

    async def terminate(self, kind: str, connection_id: str, session_id: str) -> str | None:
        """End a session. Return None on success, or the reason it could not be done.

        A relay session id is the id of the token that opened the tunnel.
        The host chooses the session ids of host sessions, so a host kill goes by connection id only.
        """
        if kind == "relay":
            close = self._tunnels.get(session_id)
            if close is None:
                return "no such tunnel"
            close()
            return None
        if kind == "host":
            return self._request_host_kill(connection_id)
        return "unknown kind"

    def _request_host_kill(self, connection_id: str) -> str | None:
        if self._kill_dir is None:
            return "host sessions cannot be ended: no kill directory"
        if not openssh_session_reaper.request_kill(self._kill_dir, connection_id):
            return "kill request not written"
        return None
