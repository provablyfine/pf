"""Accept loop + wire dispatch for the peer-credential-gated signing oracle.

Implements exactly SSH_AGENTC_REQUEST_IDENTITIES and SSH_AGENTC_SIGN_REQUEST
from the ssh-agent wire protocol; every other request type gets
SSH_AGENT_FAILURE. Narrower than real ssh-agent by design: there is no
ADD_IDENTITY support at all, even for an authorized-but-compromised peer.

Gating happens once, at accept() -- the peer is checked against `authorize`
immediately after connecting, before any protocol message is read. An
unauthorized peer's connection is simply closed with no response sent.
"""

from __future__ import annotations

import collections.abc
import dataclasses
import logging
import select
import socket
import time

import cryptography.hazmat.primitives.asymmetric.ed25519

from ... import jwk
from .. import buffer, exceptions
from . import peercred, protocol

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Identity:
    # Raw ssh-agent-wire identity blob: either a bare public key or a
    # certificate, exactly as listed to and sent back by an ssh-agent peer.
    raw: bytes
    # The private key to sign with when this identity is requested.
    key: jwk.Private


def serve_forever(
    sock: socket.socket,
    authorize: collections.abc.Callable[[socket.socket], bool],
    identities: list[Identity],
    *,
    ttl_deadline: float,
    anchor_pidfd: int,
) -> None:
    """Run the oracle's accept loop until TTL expires or the anchor process exits.

    `sock` must already be bound and listen()ing. Blocks until one of the two
    shutdown conditions fires; callers run this as the entire body of the
    forked oracle child (see spawn.py).
    """
    try:
        while True:
            remaining = ttl_deadline - time.monotonic()
            if remaining <= 0:
                logger.debug("Oracle TTL expired, shutting down")
                return
            if not peercred.pidfd_is_alive(anchor_pidfd):
                logger.debug("Oracle anchor process has exited, shutting down")
                return
            readable, _, _ = select.select([sock, anchor_pidfd], [], [], min(remaining, 1.0))
            if anchor_pidfd in readable:
                logger.debug("Oracle anchor process has exited, shutting down")
                return
            if sock not in readable:
                continue
            conn, _ = sock.accept()
            try:
                _handle_connection(conn, authorize, identities)
            except (exceptions.Error, OSError):
                logger.debug("Oracle connection error", exc_info=True)
            finally:
                conn.close()
    finally:
        sock.close()


def _handle_connection(
    conn: socket.socket,
    authorize: collections.abc.Callable[[socket.socket], bool],
    identities: list[Identity],
) -> None:
    if not authorize(conn):
        logger.debug("Oracle rejected an unauthorized peer")
        return
    wire = protocol.Connection(conn)
    while True:
        try:
            message = wire.recv_message()
        except exceptions.Error:
            return
        if message.type == protocol.SSH_AGENTC_REQUEST_IDENTITIES:
            _handle_list_identities(wire, identities)
        elif message.type == protocol.SSH_AGENTC_SIGN_REQUEST:
            _handle_sign(wire, message.contents, identities)
        else:
            wire.send_message(protocol.SSH_AGENT_FAILURE, b"")


def _handle_list_identities(wire: protocol.Connection, identities: list[Identity]) -> None:
    response = buffer.Writer()
    response.write_uint32(len(identities))
    for identity in identities:
        response.write_string(identity.raw)
        response.write_string(b"")
    wire.send_message(protocol.SSH_AGENT_IDENTITIES_ANSWER, response.to_bytes())


def _handle_sign(wire: protocol.Connection, contents: bytes, identities: list[Identity]) -> None:
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
        wire.send_message(protocol.SSH_AGENT_SIGN_RESPONSE, outer.to_bytes())
        return
    wire.send_message(protocol.SSH_AGENT_FAILURE, b"")
