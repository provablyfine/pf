"""The client-side check that an oracle endpoint is served by one of our own
processes.

The oracle asks who is calling it, on every connection, and answers only its
login shell's descendants. Until now, nothing asked the same question the other
way round: a client called `connect()` and believed whatever answered. Because
the session oracle's socket path is derived rather than secret, another local
user can be the one answering, and the client had no way to notice.

A wrong owner here is not a signing risk. The client only ever proceeds on an
identity that matches the session key it already holds, so an impostor gets
nothing out of us and can sign nothing. What it gets is for our commands to
fail, and to fail with the message a genuine expiry produces. These functions
turn that into an accurate error.

POSIX compares uids, Windows compares user SIDs, so both forms live here rather
than in either transport.
"""

from __future__ import annotations

from . import exceptions


def check_uid(path: str, peer_uid: int, our_uid: int) -> None:
    """Raise unless the peer at `path` runs as `our_uid`."""
    if peer_uid != our_uid:
        raise exceptions.OraclePeerCheckFailed(
            f"{path} is served by a process running as uid {peer_uid}, not by you (uid {our_uid})."
        )


def check_sid(path: str, peer_sid: str, our_sid: str) -> None:
    """Raise unless the server at `path` runs as `our_sid`."""
    if peer_sid != our_sid:
        raise exceptions.OraclePeerCheckFailed(
            f"{path} is served by a process running as {peer_sid}, not by you ({our_sid})."
        )


def unverifiable(path: str, reason: object) -> exceptions.OraclePeerCheckFailed:
    """The error for a peer whose owner we could not read at all.

    Failing closed is the whole point: an unreadable owner is not a verified
    one. This is why it is an `OraclePeerCheckFailed` rather than a bare
    `OSError`, which the callers would read as an expired session.
    """
    return exceptions.OraclePeerCheckFailed(f"Unable to check who serves {path}: {reason}")
