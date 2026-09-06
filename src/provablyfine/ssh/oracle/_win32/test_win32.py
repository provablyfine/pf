"""Tests for the Windows oracle."""

from __future__ import annotations

import collections.abc
import hashlib
import os
import pathlib
import subprocess
import sys
import time

import pytest

from .... import jwk
from ... import agent, cert, exceptions, serde
from . import _win32api, connection, peercred, session

_HELPER = "provablyfine.ssh.oracle._win32._test_helpers"
_CMD = os.environ.get("COMSPEC") or "C:\\Windows\\System32\\cmd.exe"
# Long enough that no test races its own oracle's TTL, short enough that a
# leaked one is gone well before the next run.
_TTL = 30.0


def _spawn_child_chain(*, depth: int, pid_file: str) -> subprocess.Popen[bytes]:
    """`cmd.exe` nested `depth` deep, with an idle Python leaf at the bottom.

    The returned Popen's pid is the *outermost* cmd.exe -- an ancestor of the
    leaf but not of this test process, which is what makes it usable both as a
    walk target and as a peer the oracle must reject.
    """
    command: list[str] = []
    for _ in range(depth):
        command += [_CMD, "/c"]
    command += [sys.executable, "-m", _HELPER, "sleep", pid_file]
    return subprocess.Popen(command)  # noqa: S603


def _read_pid_file(path: str, timeout: float = 30.0) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(path) as f:
                text = f.read().strip()
            if text:
                return int(text)
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"helper never wrote its pid to {path}")


def _pipe_is_up(name: str) -> bool:
    """Whether an oracle is still serving `name`."""
    return _win32api.named_pipe_exists(name)


def _wait_until_pipe_gone(name: str, timeout: float) -> float:
    """Seconds waited until the pipe stopped answering. Fails if it never does.

    A named pipe ceases to exist with its server process, so "gone" is a
    direct, unambiguous observation of the oracle having exited -- there is no
    stale-socket-file ambiguity to work around.
    """
    started = time.monotonic()
    deadline = started + timeout
    while time.monotonic() < deadline:
        if not _pipe_is_up(name):
            return time.monotonic() - started
        time.sleep(0.1)
    raise AssertionError(f"{name} was still serving after {timeout}s")


def _stop_oracle(anchor_pid: int) -> None:
    """Ask an oracle anchored on `anchor_pid` to exit, via the same new-login
    event a second `pf login` would use. Keeps a failed test from leaving a
    process holding a pipe name the next run wants."""
    name = session._new_login_event_name(anchor_pid, peercred.process_starttime(anchor_pid))
    event = _win32api.open_event(name)
    if event is not None:
        try:
            _win32api.set_event(event)
        finally:
            _win32api.close_handle(event)


@pytest.fixture
def key() -> jwk.Private:
    return jwk.Private.generate_ed25519()


@pytest.fixture
def self_anchored_oracle(key: jwk.Private) -> collections.abc.Iterator[str]:
    """An oracle anchored on the test process, so the test process itself is an
    authorized peer (`same_process`)."""
    name = session._spawn(key, _TTL, os.getpid())
    try:
        yield name
    finally:
        _stop_oracle(os.getpid())


def test_login_shell_identity_skips_our_own_python_and_is_stable() -> None:
    """The bug that actually bites on Windows.

    `os.getppid()` from a `console_scripts` entry point lands on the venv
    python shim, whose pid is fresh every invocation. The walk
    has to climb past our own interpreter and launcher to the shell.

    Two invocations inside *one* `cmd.exe`, because the property is not just
    "skips python" but "two separate invocations in one shell agree". A single
    invocation cannot show that.

    Note this can only be tested from a child process: under pytest the parent
    is already a stable `python.exe`, so the bug is invisible in-process.
    """
    inner = f"{sys.executable} -m {_HELPER} shell-identity"
    proc = subprocess.Popen(  # noqa: S603
        [_CMD, "/c", f"{inner} & {inner}"],
        stdout=subprocess.PIPE,
        text=True,
    )
    out, _ = proc.communicate(timeout=60)
    lines = out.split()
    assert len(lines) == 4, f"expected two 'pid creation' lines, got {out!r}"
    first, second = (lines[0], lines[1]), (lines[2], lines[3])
    assert first == second, "two invocations in one shell disagreed on the anchor"
    assert int(first[0]) == proc.pid, "anchored on our own python instead of the shell"


def test_lists_and_signs(self_anchored_oracle: str, key: jwk.Private) -> None:
    client = agent.Client(self_anchored_oracle)
    try:
        identities = list(client.list_identities())
        assert len(identities) == 1
        data = b"some data to sign"
        signature = client.sign(identities[0], data, 0)
    finally:
        client.close()
    crypto_key = key.to_crypto()
    crypto_key.public_key().verify(signature, data)  # type: ignore[union-attr]


def test_a_missing_oracle_raises_oserror() -> None:
    """`client/http_client.py` tells "log in again" apart from every other
    failure by catching `OSError`"""
    with pytest.raises(OSError):
        agent.Client(session.pipe_name(1, 1))


def test_rejects_a_peer_outside_the_anchor_ancestry(key: jwk.Private, tmp_path: pathlib.Path) -> None:
    """Anchor on a process in a *sibling* branch, not on one we spawned directly.

    Anchoring on our own child would make this test pass for the wrong reason:
    the walk only goes up, so it would never reach a descendant and would
    return False without ever exercising a rejection. With the anchor being a
    `cmd.exe` whose only descendant is its own Python leaf, this test process
    is genuinely neither the anchor nor below it.
    """
    pid_file = str(tmp_path / "leaf.pid")
    chain = _spawn_child_chain(depth=1, pid_file=pid_file)
    _read_pid_file(pid_file)
    anchor_pid = chain.pid
    name = session._spawn(key, _TTL, anchor_pid)
    try:
        client = agent.Client(name)
        # Either shape counts as a rejection and both are correct: the server
        # closes without replying, which surfaces as a broken-pipe OSError from
        # the read, or as WireSocket's own "peer closed" if the read comes back
        # empty first. What matters is that no identity is ever returned.
        with pytest.raises((OSError, exceptions.Error)):
            list(client.list_identities())
        client.close()
    finally:
        _stop_oracle(anchor_pid)
        chain.kill()
        chain.wait(timeout=30)


def test_exits_when_the_anchor_dies(key: jwk.Private, tmp_path: pathlib.Path) -> None:
    """The watchdog's first job. Nothing polls; the oracle is waiting on the
    anchor's process HANDLE, so this should be near-instant."""
    pid_file = str(tmp_path / "anchor.pid")
    chain = _spawn_child_chain(depth=0, pid_file=pid_file)
    anchor_pid = _read_pid_file(pid_file)
    name = session._spawn(key, _TTL, anchor_pid)
    assert _pipe_is_up(name)
    chain.kill()
    chain.wait(timeout=30)
    waited = _wait_until_pipe_gone(name, timeout=30)
    # Upper bound, not just "eventually": the watchdog is parked on the
    # anchor's process HANDLE, so this is a kernel wakeup rather than a poll.
    # Without a bound here, a regression to polling would still pass.
    assert waited < 10.0, f"took {waited:.1f}s to notice the anchor had died"


def test_exits_at_ttl(key: jwk.Private) -> None:
    """The watchdog's second job, and the one that matters most: this is what
    bounds how long the key exists at all."""
    name = session._spawn(key, 2.0, os.getpid())
    assert _pipe_is_up(name)
    waited = _wait_until_pipe_gone(name, timeout=30)
    assert waited >= 1.0, f"exited after {waited:.1f}s, well before its 2s TTL"
    assert waited < 10.0, f"outlived its 2s TTL by {waited - 2:.1f}s"


def test_a_second_login_displaces_the_first(key: jwk.Private) -> None:
    """the predecessor has to be asked to exit upon a new login and the
    replacement must end up serving the *new* key, not the old one."""
    replacement = jwk.Private.generate_ed25519()
    first = session._spawn(key, _TTL, os.getpid())
    # Without this the test has a silent way to pass while testing nothing: if
    # the first oracle's child never started, its name was never claimed, the
    # second _spawn succeeds on its first attempt, and the fingerprint
    # assertion below holds having exercised no displacement at all.
    assert _pipe_is_up(first), "the first oracle never came up, so nothing was displaced"
    second = session._spawn(replacement, _TTL, os.getpid())
    assert first == second, "same anchor must derive the same pipe name"
    try:
        client = agent.Client(second)
        try:
            identities = list(client.list_identities())
        finally:
            client.close()
        assert len(identities) == 1
        expected = replacement.public().ssh_fingerprint()
        assert identities[0].public_key.match_ssh_fingerprint(expected), "the displaced oracle is still serving"
    finally:
        _stop_oracle(os.getpid())


# ── connection-key oracle ────────────────────────────────────────────────────


@pytest.fixture
def cert_blob(key: jwk.Private) -> bytes:
    """A real certificate for `key`. `agent.Client` deserializes every blob it is
    handed, so a synthetic one would be rejected before reaching anything worth testing."""
    signer = jwk.Private.generate_ed25519()
    certificate = cert.Cert.create_host(
        public_key=key.public(),
        serial_number=42,
        identifier="host.example.com",
        principals=["host.example.com"],
        valid_after=1_000_000_000,
        valid_before=2_000_000_000,
        signer=signer,
    )
    return serde.serialize_cert(certificate)


def _kill_oracle_anchor(chain: subprocess.Popen[bytes]) -> None:
    """Stop a connection oracle by killing the process it is anchored on."""
    chain.kill()
    chain.wait(timeout=30)


def test_connection_oracle_lists_the_key_and_the_certificate(key: jwk.Private, cert_blob: bytes) -> None:
    """Both identities must be present and both must sign."""
    anchor = peercred.open_anchor(os.getpid())
    try:
        name = connection.spawn_oracle(key, cert_blob, anchor, ttl=_TTL)
    finally:
        peercred.close_anchor(anchor)

    client = agent.Client(name)
    try:
        identities = list(client.list_identities())
        assert [i.raw for i in identities] == [serde.serialize_public(key.public()), cert_blob]
        data = b"some data to sign"
        signatures = [client.sign(identity, data, 0) for identity in identities]
    finally:
        client.close()

    crypto_key = key.to_crypto()
    for signature in signatures:
        crypto_key.public_key().verify(signature, data)  # type: ignore[union-attr]


def test_connection_oracle_authorizes_a_descendant(key: jwk.Private, cert_blob: bytes, tmp_path: pathlib.Path) -> None:
    """`ssh.exe` is a spawned child with its own pid, so the oracle has to accept
    a descendant.

    The peer must be a descendant of *the anchor*, which is not the same thing
    as a child of the test process.

    The helper has to be started before the oracle exists, because the
    oracle's name is random and is only chosen once the anchor is open, hence
    the name file rather than an argument.
    """
    pid_file = str(tmp_path / "peer.pid")
    name_file = str(tmp_path / "pipe.name")
    chain = subprocess.Popen(  # noqa: S603
        [_CMD, "/c", sys.executable, "-m", _HELPER, "list-when-ready", pid_file, name_file],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        peer_pid = _read_pid_file(pid_file)
        # The anchor is the cmd.exe; the peer is the python it launched. If
        # these were equal the test would be checking `same_process` and the
        # ancestry walk would never run.
        assert peer_pid != chain.pid
        anchor = peercred.open_anchor(chain.pid)
        try:
            name = connection.spawn_oracle(key, cert_blob, anchor, ttl=_TTL)
        finally:
            peercred.close_anchor(anchor)

        with open(name_file, "w") as f:
            f.write(name)
        out, _ = chain.communicate(timeout=60)
        expected = [
            hashlib.sha256(serde.serialize_public(key.public())).hexdigest()[:16],
            hashlib.sha256(cert_blob).hexdigest()[:16],
        ]
        assert out.split() == expected, f"a descendant of the anchor was not served: {out!r}"
    finally:
        _kill_oracle_anchor(chain)


def test_connection_oracle_rejects_a_peer_outside_the_anchor_ancestry(
    key: jwk.Private, cert_blob: bytes, tmp_path: pathlib.Path
) -> None:
    """Anchor on a sibling branch, so this process is neither the anchor nor
    below it -- anchoring on our own child would return False without the walk
    ever reaching a descendant, passing for the wrong reason."""
    pid_file = str(tmp_path / "leaf.pid")
    chain = _spawn_child_chain(depth=1, pid_file=pid_file)
    try:
        _read_pid_file(pid_file)
        anchor = peercred.open_anchor(chain.pid)
        try:
            name = connection.spawn_oracle(key, cert_blob, anchor, ttl=_TTL)
        finally:
            peercred.close_anchor(anchor)

        client = agent.Client(name)
        # Either shape counts as a rejection: the server closes without
        # replying, surfacing as a broken-pipe OSError, or as WireSocket's own
        # "peer closed" if the read comes back empty first. What matters is
        # that no identity is ever returned.
        with pytest.raises((OSError, exceptions.Error)):
            list(client.list_identities())
        client.close()
    finally:
        _kill_oracle_anchor(chain)


def test_connection_oracle_exits_when_its_anchor_dies(
    key: jwk.Private, cert_blob: bytes, tmp_path: pathlib.Path
) -> None:
    """A 60s TTL is the backstop, not the mechanism: a `pf ssh` that ends in two
    seconds must not leave the key alive for another 58."""
    pid_file = str(tmp_path / "anchor.pid")
    chain = _spawn_child_chain(depth=0, pid_file=pid_file)
    anchor_pid = _read_pid_file(pid_file)
    anchor = peercred.open_anchor(anchor_pid)
    try:
        name = connection.spawn_oracle(key, cert_blob, anchor, ttl=_TTL)
    finally:
        peercred.close_anchor(anchor)
    assert _pipe_is_up(name)
    _kill_oracle_anchor(chain)
    waited = _wait_until_pipe_gone(name, timeout=30)
    assert waited < 10.0, f"took {waited:.1f}s to notice the anchor had died"


def test_is_descendant_of_walks_a_real_chain(tmp_path: pathlib.Path) -> None:
    """Three real hops, not a synthetic one: the leaf's ancestry is
    python.exe -> cmd.exe -> cmd.exe, and only the outermost is the anchor."""
    pid_file = str(tmp_path / "leaf.pid")
    chain = _spawn_child_chain(depth=2, pid_file=pid_file)
    try:
        leaf_pid = _read_pid_file(pid_file)
        anchor = peercred.open_anchor(chain.pid)
        try:
            assert peercred.is_descendant_of(leaf_pid, anchor)
            assert not peercred.is_descendant_of(os.getpid(), anchor)
        finally:
            peercred.close_anchor(anchor)
    finally:
        chain.kill()
        chain.wait(timeout=30)
