"""Tests for the client-side check that an oracle endpoint is ours.

The comparison is here because a mismatch needs a peer running as somebody
else, which no unprivileged test can arrange: the code under test is reached
with the two ids it would have read. What the syscalls really return is covered
next door, in `oracle/_posix/test_peercred.py` and `oracle/_win32/test_win32.py`,
against peers that are ours -- enough to prove the plumbing, and enough to prove
a legitimate connection is never rejected.
"""

from __future__ import annotations

import socket
import sys

import pytest

from . import exceptions, peer_owner


def test_a_peer_running_as_another_user_is_rejected_by_name() -> None:
    with pytest.raises(exceptions.OraclePeerCheckFailed) as excinfo:
        peer_owner.check_uid("/run/user/1000/pf-so-abc/s", 65534, 1000)
    message = str(excinfo.value)
    assert "/run/user/1000/pf-so-abc/s" in message
    assert "65534" in message
    assert "1000" in message


def test_the_same_uid_is_accepted() -> None:
    peer_owner.check_uid("/run/user/1000/pf-so-abc/s", 1000, 1000)


def test_a_pipe_served_by_another_user_is_rejected_by_name() -> None:
    with pytest.raises(exceptions.OraclePeerCheckFailed) as excinfo:
        peer_owner.check_sid(r"\\.\pipe\pf-so-abc", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1001")
    message = str(excinfo.value)
    assert "S-1-5-21-1-2-3-1002" in message
    assert "S-1-5-21-1-2-3-1001" in message


def test_an_unreadable_owner_is_a_failure_not_a_pass() -> None:
    with pytest.raises(exceptions.OraclePeerCheckFailed) as excinfo:
        raise peer_owner.unverifiable("/run/user/1000/pf-so-abc/s", PermissionError(13, "Permission denied"))
    assert "Unable to check who serves /run/user/1000/pf-so-abc/s" in str(excinfo.value)


def test_a_rejection_is_never_mistaken_for_an_expired_session() -> None:
    """The mapping this whole check exists to break.

    Both client paths read an `OSError` from the agent as "no oracle, log in
    again". A foreign owner has to escape that, so it must be an
    `exceptions.Error` (which the CLI prints) and not an `OSError` (which it
    does not).
    """
    assert not issubclass(exceptions.OraclePeerCheckFailed, OSError)
    assert issubclass(exceptions.OraclePeerCheckFailed, exceptions.Error)


@pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX unavailable on older Windows")
def test_connecting_to_an_endpoint_of_ours_passes_the_check() -> None:
    """End to end, over a real socket: the check must not reject our own oracle."""
    from . import _posix

    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _posix._check_owner(a, "socketpair")
    finally:
        a.close()
        b.close()
