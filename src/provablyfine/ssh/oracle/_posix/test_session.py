"""Tests for the session-key oracle's authorization model and spawn/lookup plumbing."""

from __future__ import annotations

import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

import pytest

from .... import jwk
from ... import agent, exceptions
from . import peercred, session, spawn

pytestmark = pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="oracle only supports Linux and macOS")


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
    assert session.current_socket_path(
        "https://a.example/pf/t/00000000-0000-0000-0000-000000000001/"
    ) == session.current_socket_path("https://a.example/pf/t/00000000-0000-0000-0000-000000000001/")


def test_socket_path_differs_for_different_parents() -> None:
    url = "https://a.example/pf/t/00000000-0000-0000-0000-000000000001/"
    a = session.socket_path(parent_pid=111, parent_starttime=222, directory_url=url)
    b = session.socket_path(parent_pid=111, parent_starttime=223, directory_url=url)
    c = session.socket_path(parent_pid=112, parent_starttime=222, directory_url=url)
    assert len({a, b, c}) == 3


def test_socket_path_differs_for_different_tenants() -> None:
    d = session.socket_path(
        parent_pid=111,
        parent_starttime=222,
        directory_url="https://a.example/pf/t/00000000-0000-0000-0000-000000000001/",
    )
    e = session.socket_path(
        parent_pid=111,
        parent_starttime=222,
        directory_url="https://b.example/pf/t/00000000-0000-0000-0000-000000000001/",
    )
    assert d != e


# Stand-ins for `$XDG_RUNTIME_DIR`/`tempfile.gettempdir()`'s usual values,
# spelled to avoid ruff's S108 (real hardcoded-tempdir) check: these are
# mocked return values, never touched on disk.
_FAKE_RUNTIME_DIR = "/fake-run/user/1000"
_FAKE_TEMPDIR = "/fake-tmp"


def test_socket_path_prefers_xdg_runtime_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", _FAKE_RUNTIME_DIR)
    monkeypatch.setattr(session.tempfile, "gettempdir", lambda: _FAKE_TEMPDIR)
    path = session.socket_path(parent_pid=111, parent_starttime=222, directory_url="https://a.example/")
    assert path.startswith(_FAKE_RUNTIME_DIR + "/")


def test_socket_path_falls_back_to_tempdir_without_xdg_runtime_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(session.tempfile, "gettempdir", lambda: _FAKE_TEMPDIR)
    path = session.socket_path(parent_pid=111, parent_starttime=222, directory_url="https://a.example/")
    assert path.startswith(_FAKE_TEMPDIR + "/")


def test_socket_path_falls_back_silently_when_xdg_runtime_dir_is_too_long(monkeypatch: pytest.MonkeyPatch) -> None:
    # A long $XDG_RUNTIME_DIR just means missing out on the extra protection,
    # not a hard failure -- unlike an equally long $TMPDIR, which still is one
    # (see the next test).
    monkeypatch.setenv("XDG_RUNTIME_DIR", _FAKE_RUNTIME_DIR + "x" * 100)
    monkeypatch.setattr(session.tempfile, "gettempdir", lambda: _FAKE_TEMPDIR)
    path = session.socket_path(parent_pid=111, parent_starttime=222, directory_url="https://a.example/")
    assert path.startswith(_FAKE_TEMPDIR + "/")


def test_socket_path_rejects_a_too_long_tempdir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(session.tempfile, "gettempdir", lambda: _FAKE_TEMPDIR + "x" * 100)
    with pytest.raises(exceptions.InvalidConfiguration, match="too long"):
        session.socket_path(parent_pid=111, parent_starttime=222, directory_url="https://a.example/")


def test_bind_socket_refuses_a_foreign_directory() -> None:
    # The closest stand-in for the cross-uid squatting of issue #165 that can
    # be tested without a second user: a *file* at the socket's directory
    # path must produce a clear refusal, not a bare EACCES/ENOTDIR from bind().
    base = tempfile.mkdtemp(prefix="pf-oracle-test-")
    try:
        directory = os.path.join(base, "pf-so-foreign")
        with open(directory, "w") as f:
            f.write("")
        with pytest.raises(exceptions.InvalidConfiguration, match="not a directory"):
            spawn.bind_socket(os.path.join(directory, "s"))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_bind_socket_tightens_a_loose_mode_own_directory() -> None:
    # A directory we own but left too open (e.g. from a pre-fix pf) must be
    # tightened to 0700, not reused as-is.
    base = tempfile.mkdtemp(prefix="pf-oracle-test-")
    try:
        directory = os.path.join(base, "pf-so-loose-mode")
        os.mkdir(directory)
        os.chmod(directory, 0o755)  # noqa: S103
        path = os.path.join(directory, "s")
        sock = spawn.bind_socket(path)
        try:
            assert stat.S_IMODE(os.lstat(directory).st_mode) == 0o700
        finally:
            sock.close()
            os.unlink(path)
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.mark.xdist_group(name="pf-session-oracle")
def test_spawn_and_sign_from_the_same_shell() -> None:
    # xdist_group: pytest-xdist workers share one parent process, which is
    # what current_socket_path() derives from -- without this, a concurrent
    # test in another worker doing the same thing races on the identical
    # socket path (see tests/test_oidc.py's _create_session_key() docstring).
    directory_url = "https://a.example/pf/t/00000000-0000-0000-0000-000000000001/"
    key = jwk.Private.generate_ed25519()
    path = session.spawn_oracle(key, directory_url, ttl=10)
    try:
        assert path == session.current_socket_path(directory_url)
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


@pytest.mark.xdist_group(name="pf-session-oracle")
def test_superseded_oracle_ttl_expiry_does_not_delete_newer_socket() -> None:
    """Try to verify that two oracles racing to the same socket do nothing crazy."""
    directory_url = "https://a.example/pf/t/00000000-0000-0000-0000-000000000001/"
    key_a = jwk.Private.generate_ed25519()
    path = session.spawn_oracle(key_a, directory_url, ttl=1)
    key_b = jwk.Private.generate_ed25519()
    assert session.spawn_oracle(key_b, directory_url, ttl=10) == path
    try:
        time.sleep(2.5)  # let key_a's oracle hit its 1s TTL and shut down
        assert os.path.exists(path), "the still-live second oracle's socket was deleted"
        client = agent.Client(path)
        try:
            identities = list(client.list_identities())
            assert len(identities) == 1
            data = b"still alive"
            signature = client.sign(identities[0], data, 0)
            key_b.to_crypto().public_key().verify(signature, data)  # type: ignore[union-attr]
        finally:
            client.close()
    finally:
        _cleanup(path)


def test_authorize_accepts_a_descendant_of_the_anchor() -> None:
    # Our own process's parent stands in for "the login shell" here -- the
    # test process itself is a real, kernel-verifiable descendant of it.
    anchor = peercred.open_anchor(os.getppid())
    try:
        authorize = session.authorize(anchor, session_id=None, tty_dev=None)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert authorize(a)
        finally:
            a.close()
            b.close()
    finally:
        peercred.close_anchor(anchor)


def test_authorize_rejects_an_unrelated_anchor() -> None:
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        anchor = peercred.open_anchor(unrelated.pid)
        try:
            authorize = session.authorize(anchor, session_id=None, tty_dev=None)
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                assert not authorize(a)
            finally:
                a.close()
                b.close()
        finally:
            peercred.close_anchor(anchor)
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_authorize_enforces_session_id_when_anchor_has_one() -> None:
    anchor = peercred.open_anchor(os.getppid())
    try:
        # A session id that cannot possibly match ours forces rejection even
        # though the parent-process factor alone would pass.
        authorize = session.authorize(anchor, session_id=0x7FFFFFFE, tty_dev=None)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert not authorize(a)
        finally:
            a.close()
            b.close()
    finally:
        peercred.close_anchor(anchor)


def test_authorize_accepts_when_session_id_matches() -> None:
    # The socketpair peer below is *this* process, so its own session id
    # (peer_session_facts() reads it fresh off the connection at accept
    # time) is what must be matched here -- distinguishes "asid comparison
    # rejects everything" from "asid comparison actually accepts a real
    # match", which the mismatch-only test above can't tell apart.
    own_session_id = peercred.parent_session_id(os.getpid())
    if own_session_id is None:
        pytest.skip("no audit session id in this environment (bare container/CI shell)")
    anchor = peercred.open_anchor(os.getppid())
    try:
        authorize = session.authorize(anchor, session_id=own_session_id, tty_dev=None)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert authorize(a)
        finally:
            a.close()
            b.close()
    finally:
        peercred.close_anchor(anchor)


def test_audit_session_id_unset_is_none_or_a_real_value() -> None:
    # Just confirms the primitive doesn't blow up and returns a sane type --
    # whether it's set at all depends on the environment this test runs in
    # (PAM-managed login vs. a bare container/CI shell).
    value = peercred.parent_session_id(os.getpid())
    assert value is None or isinstance(value, int)
