"""Tests for the session-key oracle's authorization model and spawn/lookup plumbing. """

from __future__ import annotations

import os
import socket
import subprocess
import sys

import pytest

from ... import jwk
from .. import agent
from . import peercred, session

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="oracle is Linux-only")


def _cleanup(path: str) -> None:
    directory = os.path.dirname(path)
    try:
        os.unlink(path)
    except OSError:
        pass
    try:
        os.rmdir(directory)
    except OSError:
        pass


def test_current_socket_path_is_deterministic() -> None:
    assert session.current_socket_path() == session.current_socket_path()


def test_socket_path_differs_for_different_parents() -> None:
    a = session.socket_path(parent_pid=111, parent_starttime=222)
    b = session.socket_path(parent_pid=111, parent_starttime=223)
    c = session.socket_path(parent_pid=112, parent_starttime=222)
    assert len({a, b, c}) == 3


@pytest.mark.xdist_group(name="pf-session-oracle")
def test_spawn_and_sign_from_the_same_shell() -> None:
    # xdist_group: pytest-xdist workers share one parent process, which is
    # what current_socket_path() derives from -- without this, a concurrent
    # test in another worker doing the same thing races on the identical
    # socket path (see tests/test_oidc.py's _create_session_key() docstring).
    key = jwk.Private.generate_ed25519()
    path = session.spawn_oracle(key, ttl=10)
    try:
        assert path == session.current_socket_path()
        client = agent.Client(path)
        try:
            identities = list(client.list_identities())
            assert len(identities) == 1
            data = b"session key test payload"
            signature = client.sign(identities[0], data, 0)
            key.to_crypto().public_key().verify(signature, data)  # type: ignore[union-attr]
        finally:
            client.close()
    finally:
        _cleanup(path)


def test_authorize_accepts_a_descendant_of_the_anchor() -> None:
    # Our own process's parent stands in for "the login shell" here -- the
    # test process itself is a real, kernel-verifiable descendant of it.
    anchor_pidfd = os.pidfd_open(os.getppid())
    try:
        authorize = session.authorize(anchor_pidfd, session_id=None, tty_dev=None)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert authorize(a)
        finally:
            a.close()
            b.close()
    finally:
        os.close(anchor_pidfd)


def test_authorize_rejects_an_unrelated_anchor() -> None:
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        anchor_pidfd = os.pidfd_open(unrelated.pid)
        try:
            authorize = session.authorize(anchor_pidfd, session_id=None, tty_dev=None)
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                assert not authorize(a)
            finally:
                a.close()
                b.close()
        finally:
            os.close(anchor_pidfd)
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_authorize_enforces_session_id_when_anchor_has_one() -> None:
    anchor_pidfd = os.pidfd_open(os.getppid())
    try:
        # A session id that cannot possibly match ours forces rejection even
        # though the parent-process factor alone would pass.
        authorize = session.authorize(anchor_pidfd, session_id=0x7FFFFFFE, tty_dev=None)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert not authorize(a)
        finally:
            a.close()
            b.close()
    finally:
        os.close(anchor_pidfd)


def test_audit_session_id_unset_is_none_or_a_real_value() -> None:
    # Just confirms the primitive doesn't blow up and returns a sane type --
    # whether it's set at all depends on the environment this test runs in
    # (PAM-managed login vs. a bare container/CI shell).
    value = peercred.audit_session_id(os.getpid())
    assert value is None or isinstance(value, int)
