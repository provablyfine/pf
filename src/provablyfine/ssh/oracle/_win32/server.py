"""Accept loop + wire dispatch for the oracle, on Windows.

Same contract as `.._posix.server`: exactly SSH_AGENTC_REQUEST_IDENTITIES and
SSH_AGENTC_SIGN_REQUEST are implemented, every other request type gets
SSH_AGENT_FAILURE, and there is no ADD_IDENTITY support at all -- narrower
than a real ssh-agent by design, even for an authorized-but-compromised peer.

Gating happens once, immediately after a client connects and before any
protocol byte is read; an unauthorized peer is simply dropped with no response.

Shutdown implemented by a watchdog thread which waits on the
anchor's process HANDLE, the new-login event, and the TTL, and calls
`os._exit()`.
"""

from __future__ import annotations

import collections.abc
import dataclasses
import logging
import os
import threading
import time

import cryptography.hazmat.primitives.asymmetric.ed25519

from .... import jwk
from ... import buffer, exceptions, wire
from . import _win32api, peercred

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Identity:
    # Raw ssh-agent-wire identity blob: either a bare public key or a
    # certificate, exactly as listed to and sent back by an ssh-agent peer.
    raw: bytes
    # The private key to sign with when this identity is requested.
    key: jwk.Private


class _HandleTransport:
    """`wire.Transport` over a connected pipe HANDLE."""

    def __init__(self, handle: int) -> None:
        self._handle = handle

    def recv(self, size: int) -> bytes:
        return _win32api.read_file(self._handle, size)

    def send(self, data: bytes) -> int:
        return _win32api.write_file(self._handle, data)

    def close(self) -> None:
        pass


def _watchdog(anchor: peercred.Anchor, new_login_event: int | None, deadline: float) -> None:
    handles = (anchor.handle,) if new_login_event is None else (anchor.handle, new_login_event)
    timeout_ms = int(max(0.0, deadline - time.monotonic()) * 1000)
    index = _win32api.wait_for_any(handles, timeout_ms)
    if index is None:
        logger.debug("Oracle TTL expired, exiting")
    elif index == 0:
        logger.debug("Oracle anchor process has exited, exiting")
    else:
        logger.debug("Oracle replaced by a newer login, exiting")
    logging.shutdown()
    # Not sys.exit(): this runs on a non-main thread, where SystemExit only
    # ends the thread. os._exit() is also what we actually want -- the process
    # holds a private key, and the shortest path to it not existing is best.
    os._exit(0)


def serve(
    handle: int,
    authorize: collections.abc.Callable[[int], bool],
    identities: list[Identity],
    *,
    ttl: float,
    anchor: peercred.Anchor,
    new_login_event: int | None = None,
) -> None:
    """Serve until the watchdog ends the process. Never returns normally.

    `handle` must be an already-created listening pipe. `authorize` receives
    that handle rather than a socket: on Windows the peer's identity is read
    off the pipe itself, via `GetNamedPipeClientProcessId`.

    `ttl` is a duration, not a deadline
    """
    threading.Thread(
        target=_watchdog,
        args=(anchor, new_login_event, time.monotonic() + ttl),
        daemon=True,
        name="pf-oracle-watchdog",
    ).start()
    while True:
        _win32api.connect_named_pipe(handle)
        try:
            if authorize(handle):
                _serve_messages(handle, identities)
            else:
                logger.debug("Oracle rejected an unauthorized peer")
        except (exceptions.Error, OSError):
            logger.debug("Oracle connection error", exc_info=True)
        finally:
            _win32api.disconnect_named_pipe(handle)


def _serve_messages(handle: int, identities: list[Identity]) -> None:
    framed = wire.WireSocket(_HandleTransport(handle))
    while True:
        try:
            message = framed.recv_message()
        except exceptions.Error:
            return
        if message.type == wire.SSH_AGENTC_REQUEST_IDENTITIES:
            _handle_list_identities(framed, identities)
        elif message.type == wire.SSH_AGENTC_SIGN_REQUEST:
            _handle_sign(framed, message.contents, identities)
        else:
            framed.send_message(wire.SSH_AGENT_FAILURE, b"")


def _handle_list_identities(framed: wire.WireSocket, identities: list[Identity]) -> None:
    response = buffer.Writer()
    response.write_uint32(len(identities))
    for identity in identities:
        response.write_string(identity.raw)
        response.write_string(b"")
    framed.send_message(wire.SSH_AGENT_IDENTITIES_ANSWER, response.to_bytes())


def _handle_sign(framed: wire.WireSocket, contents: bytes, identities: list[Identity]) -> None:
    request = buffer.Reader(contents)
    raw_key = request.read_string()
    data = request.read_string()
    _flags = request.read_uint32()
    for identity in identities:
        if identity.raw != raw_key:
            continue
        crypto_key = identity.key.to_crypto()
        assert isinstance(crypto_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)
        signature = crypto_key.sign(data)
        inner = buffer.Writer()
        inner.write_string(b"ssh-ed25519")
        inner.write_string(signature)
        outer = buffer.Writer()
        outer.write_string(inner.to_bytes())
        framed.send_message(wire.SSH_AGENT_SIGN_RESPONSE, outer.to_bytes())
        return
    framed.send_message(wire.SSH_AGENT_FAILURE, b"")
