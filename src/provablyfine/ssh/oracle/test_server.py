"""Unit-level regression tests for `serve_forever`'s accept loop"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

import pytest

from ... import jwk
from .. import serde
from . import peercred, server

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


def test_ttl_expires_even_with_a_stalled_connection() -> None:
    """An accepted connection that never sends anything used to block
    forever on recv() with no timeout, starving the TTL/anchor-liveness
    checks above the accept() call of ever running again -- so the oracle
    would neither expire at TTL nor react to its anchor dying while that one
    connection stayed open.
    """
    # A short mkdtemp() path rather than pytest's tmp_path fixture: the
    # latter's pytest-of-<user>/pytest-<N>/<test name> nesting routinely
    # blows past macOS's ~104-byte AF_UNIX sun_path limit (confirmed: 94
    # bytes for tmp_path alone, before even appending a filename) -- a
    # test-harness artifact, not a constraint real oracle callers hit, since
    # they use tempfile.mkdtemp()/gettempdir() directly (see connection.py /
    # session.py), which stays well under the limit.
    socket_path = os.path.join(tempfile.mkdtemp(prefix="pf-test-"), "oracle.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    listener.listen(1)
    key = jwk.Private.generate_ed25519()
    identity = server.Identity(raw=serde.serialize_public(key.public()), key=key)
    anchor = peercred.open_anchor(os.getpid())
    try:
        thread = threading.Thread(
            target=server.serve_forever,
            args=(listener, lambda _conn: True, [identity]),
            kwargs={"ttl_deadline": time.monotonic() + 0.5, "anchor": anchor},
        )
        thread.start()
        try:
            stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stalled.connect(socket_path)
            try:
                thread.join(timeout=5)
                assert not thread.is_alive(), "TTL expiry was starved by the stalled connection"
            finally:
                stalled.close()
        finally:
            thread.join(timeout=5)
    finally:
        peercred.close_anchor(anchor)
        _cleanup(socket_path)


def test_anchor_death_expires_even_with_a_stalled_connection() -> None:
    """Same starvation as above, but for the other shutdown condition: the
    anchor process (e.g. the login shell) exiting must still be noticed and
    shut the oracle down even while a connection is open and idle.
    """
    socket_path = os.path.join(tempfile.mkdtemp(prefix="pf-test-"), "oracle.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socket_path)
    listener.listen(1)
    key = jwk.Private.generate_ed25519()
    identity = server.Identity(raw=serde.serialize_public(key.public()), key=key)
    anchor = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        anchor_handle = peercred.open_anchor(anchor.pid)
        try:
            thread = threading.Thread(
                target=server.serve_forever,
                args=(listener, lambda _conn: True, [identity]),
                kwargs={"ttl_deadline": time.monotonic() + 30, "anchor": anchor_handle},
            )
            thread.start()
            try:
                stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                stalled.connect(socket_path)
                try:
                    anchor.terminate()
                    anchor.wait(timeout=5)
                    thread.join(timeout=5)
                    assert not thread.is_alive(), "anchor death was starved by the stalled connection"
                finally:
                    stalled.close()
            finally:
                thread.join(timeout=5)
        finally:
            peercred.close_anchor(anchor_handle)
    finally:
        if anchor.poll() is None:
            anchor.terminate()
        anchor.wait(timeout=5)
        _cleanup(socket_path)
