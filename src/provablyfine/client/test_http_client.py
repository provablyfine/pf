"""Tests for `AgentSigner`'s check of the signatures it gets back.

A real UNIX socket and a real `ssh.agent.Client` peer, served by a small
in-process fake agent (the pattern of `ssh/oracle/_posix/test_connection.py`):
no mocks. The fake agent is the "buggy or malicious oracle" of the issue: it
lists the honest public key but chooses for itself what to hand back when
asked to sign.
"""

from __future__ import annotations

import collections.abc
import os
import shutil
import socket
import sys
import tempfile
import threading
import typing

import cryptography.hazmat.primitives.asymmetric.ed25519
import provablyfine_client as pfc
import pytest

from .. import jwk, ssh
from . import http_client

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX fake agent is posix-only")


class _FakeAgent:
    """An ssh-agent over a UNIX socket whose signing answer you choose."""

    def __init__(self, path: str, public_key: jwk.Public, sign: collections.abc.Callable[[bytes], bytes]) -> None:
        self._sign = sign
        self._raw_key = ssh.serde.serialize_public(public_key)
        self._stopped = False
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(path)
        self._listener.listen(1)
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stopped = True
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()
        self._thread.join(timeout=5.0)

    def _run(self) -> None:
        while not self._stopped:
            try:
                conn = self._listener.accept()[0]
            except OSError:
                return
            with conn, ssh.wire.WireSocket(conn) as framed:
                while not self._stopped:
                    try:
                        message = framed.recv_message()
                    except (ssh.exceptions.Error, OSError):
                        break
                    self._handle(framed, message)

    def _handle(self, framed: ssh.wire.WireSocket, message: ssh.wire.Message) -> None:
        if message.type == ssh.wire.SSH_AGENTC_REQUEST_IDENTITIES:
            answer = ssh.buffer.Writer()
            answer.write_uint32(1)
            answer.write_string(self._raw_key)
            answer.write_string(b"fake")
            framed.send_message(ssh.wire.SSH_AGENT_IDENTITIES_ANSWER, answer.to_bytes())
        elif message.type == ssh.wire.SSH_AGENTC_SIGN_REQUEST:
            request = ssh.buffer.Reader(message.contents)
            _key = request.read_string()
            data = request.read_string()
            _flags = request.read_uint32()
            inner = ssh.buffer.Writer()
            inner.write_string(b"ssh-ed25519")
            inner.write_string(self._sign(data))
            outer = ssh.buffer.Writer()
            outer.write_string(inner.to_bytes())
            framed.send_message(ssh.wire.SSH_AGENT_SIGN_RESPONSE, outer.to_bytes())
        else:
            framed.send_message(ssh.wire.SSH_AGENT_FAILURE, b"")


@pytest.fixture
def agent_path() -> typing.Generator[str]:
    """A directory short enough to hold an AF_UNIX socket"""
    directory = tempfile.mkdtemp(prefix="pf-fake-agent-", dir="/tmp")
    try:
        yield os.path.join(directory, "s")
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture
def keys() -> tuple[jwk.Private, jwk.Private]:
    """The key the signer expects, and a second key the fake agent can sign with."""
    return jwk.Private.generate_ed25519(), jwk.Private.generate_ed25519()


def _signer(key: jwk.Private, path: str, prefix: str) -> http_client.AgentSigner:
    return http_client.AgentSigner(prefix, key.public(), path, unreachable=lambda e: pfc.exceptions.UI(str(e)))


def _ed25519_private(key: jwk.Private) -> cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey:
    crypto_key = key.to_crypto()
    assert isinstance(crypto_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)
    return crypto_key


def _signature_from(
    agent_path: str, key: jwk.Private, sign: collections.abc.Callable[[bytes], bytes], prefix: str
) -> bytes:
    fake = _FakeAgent(agent_path, key.public(), sign)
    fake.start()
    try:
        return _signer(key, agent_path, prefix).sign(b"payload")
    finally:
        fake.stop()


def test_valid_signature_is_passed_through(agent_path: str, keys: tuple[jwk.Private, jwk.Private]) -> None:
    expected, _other = keys
    signature = _signature_from(agent_path, expected, lambda d: _ed25519_private(expected).sign(d), "session")
    public_key = expected.public().to_crypto()
    assert isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey)
    public_key.verify(signature, b"payload")


def test_garbage_signature_from_session_oracle_raises_key_expired(
    agent_path: str, keys: tuple[jwk.Private, jwk.Private]
) -> None:
    expected, _other = keys
    fingerprint = expected.public().ssh_fingerprint()
    with pytest.raises(pfc.exceptions.KeyExpired) as excinfo:
        _signature_from(agent_path, expected, lambda d: os.urandom(64), "session")
    assert excinfo.value.key_type == "session"
    assert str(excinfo.value) == (
        f"The signing oracle for session key {fingerprint} produced an invalid signature. "
        "The oracle may be buggy or compromised."
    )


def test_garbage_signature_from_account_agent_raises_ui(agent_path: str, keys: tuple[jwk.Private, jwk.Private]) -> None:
    expected, _other = keys
    fingerprint = expected.public().ssh_fingerprint()
    with pytest.raises(pfc.exceptions.UI) as excinfo:
        _signature_from(agent_path, expected, lambda d: os.urandom(64), "account")
    assert f"invalid signature for account key {fingerprint}" in str(excinfo.value)


def test_signature_from_a_different_key_is_rejected(agent_path: str, keys: tuple[jwk.Private, jwk.Private]) -> None:
    expected, other = keys
    with pytest.raises(pfc.exceptions.KeyExpired):
        _signature_from(agent_path, expected, lambda d: _ed25519_private(other).sign(d), "session")


def test_wrong_length_signature_is_rejected(agent_path: str, keys: tuple[jwk.Private, jwk.Private]) -> None:
    expected, _other = keys
    with pytest.raises(pfc.exceptions.KeyExpired):
        _signature_from(agent_path, expected, lambda d: b"too short", "session")
