"""End connections on request.

The bastion relay calls this when the server sends a signed `terminate` token.
A connection has tunnels that the relay carries, and a session on the host.

Tunnels are closed here.
The session is ended by the session reaper, which runs with the rights to do it.
This process only leaves a request in a directory that the reaper reads.
"""

from __future__ import annotations

import collections.abc
import logging

from . import openssh_session_reaper

logger = logging.getLogger(__name__)


class Terminator:
    """Ends the connections of one host."""

    def __init__(self, kill_dir: str | None) -> None:
        self._kill_dir = kill_dir
        # The tunnels of each connection, by the id of the token that opened them.
        self._tunnels: dict[str, dict[str, collections.abc.Callable[[], None]]] = {}

    def track_tunnel(self, connection_id: str, token_id: str, close: collections.abc.Callable[[], None]) -> None:
        self._tunnels.setdefault(connection_id, {})[token_id] = close

    def untrack_tunnel(self, connection_id: str, token_id: str) -> None:
        tunnels = self._tunnels.get(connection_id, {})
        tunnels.pop(token_id, None)
        if not tunnels:
            self._tunnels.pop(connection_id, None)

    def terminate(self, connection_id: str) -> str | None:
        """End a connection. Return None on success, or the reason nothing could be done.

        It closes the tunnels that this relay carries for the connection.
        It also leaves a request for the session reaper, which ends the session on the host.
        Either one is enough, because the other follows: sshd ends the session when its connection closes,
        and the tunnel closes when the session ends.
        """
        closed = 0
        for close in list(self._tunnels.get(connection_id, {}).values()):
            close()
            closed += 1
        reason = self._request_host_kill(connection_id)
        if closed or reason is None:
            return None
        return reason

    def _request_host_kill(self, connection_id: str) -> str | None:
        if self._kill_dir is None:
            return "no kill directory"
        if not openssh_session_reaper.request_kill(self._kill_dir, connection_id):
            return "kill request not written"
        return None
