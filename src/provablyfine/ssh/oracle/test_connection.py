"""End-to-end tests for the connection-key oracle: real fork, real UNIX
socket, a real `ssh.agent.Client` peer -- no mocks.

Automated coverage here deliberately uses a plain (non-certificate) blob as
the stand-in "second identity" rather than a real SSH certificate: a real
`ssh.agent.Client.list_identities()` round-trips every listed identity
through `serde.deserialize_public()`, which only understands bare-key-format
blobs, not certificate-format ones -- exercising a genuine certificate
identity this way would fail for a reason that has nothing to do with the
oracle (a real `ssh` client treats every listed blob as opaque and never
does this deserialization). The certificate-listing behavior itself is
covered by the manual `pf ssh <host>` verification in the plan instead.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys

import pytest

from ... import jwk
from .. import agent, serde
from . import connection

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="oracle is Linux-only")

_UNAUTHORIZED_PROBE = """
import socket
import sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])
sock.settimeout(2.0)
try:
    data = sock.recv(1)
    print("REJECTED" if data == b"" else "UNEXPECTED_DATA")
except OSError:
    print("REJECTED")
"""


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


def test_lists_and_signs_both_identities() -> None:
    key = jwk.Private.generate_ed25519()
    second_identity_key = jwk.Private.generate_ed25519()
    second_identity_blob = serde.serialize_public(second_identity_key.public())

    anchor_pidfd = os.pidfd_open(os.getpid())
    path = connection.spawn_oracle(key, second_identity_blob, anchor_pidfd, ttl=10)
    try:
        client = agent.Client(path)
        try:
            identities = list(client.list_identities())
            assert len(identities) == 2

            data = b"some data to sign"
            crypto_key = key.to_crypto()
            for identity in identities:
                signature = client.sign(identity, data, 0)
                crypto_key.public_key().verify(signature, data)  # type: ignore[union-attr]
        finally:
            client.close()
    finally:
        _cleanup(path)


def test_rejects_an_unrelated_peer() -> None:
    key = jwk.Private.generate_ed25519()
    cert_blob = serde.serialize_public(key.public())
    anchor_pidfd = os.pidfd_open(os.getpid())
    path = connection.spawn_oracle(key, cert_blob, anchor_pidfd, ttl=10)
    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _UNAUTHORIZED_PROBE, path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.stdout.strip() == "REJECTED"
    finally:
        _cleanup(path)


def test_authorize_accepts_the_anchored_process_itself() -> None:
    anchor_pidfd = os.pidfd_open(os.getpid())
    try:
        authorize = connection.authorize(anchor_pidfd)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            assert authorize(a)
        finally:
            a.close()
            b.close()
    finally:
        os.close(anchor_pidfd)
