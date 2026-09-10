"""Connection-key oracle: serve one `pf ssh` invocation and no more.

Unlike `session`, this model has no new-login event and no Windows-session-id
factor. The name is random and per-invocation, so there is no predecessor to
displace, and the binding is the anchor alone. The peer here is a
*descendant* of the anchor, and the check is `same_process or is_descendant_of`
which is wider than the posix check: `same_process`.
"""

from __future__ import annotations

import collections.abc
import logging
import secrets

from .... import jwk
from ... import exceptions, serde
from . import _win32api, peercred, server, spawn

logger = logging.getLogger(__name__)


def pipe_name(token: str) -> str:
    return f"\\\\.\\pipe\\pf-oracle-{token}"


def spawn_oracle(key: jwk.Private, cert_blob: bytes, anchor: peercred.Anchor, ttl: float = 60) -> str:
    """Spawn a connection-key oracle bound to `anchor` and its descendants.

    Lists both the bare public key and the certificate as separate identities,
    both signed by `key` -- `ssh` invoked with `CertificateFile=...` +
    `IdentitiesOnly=yes` looks the identity up by the certificate blob, not the
    bare key, so both must be present.

    Returns the oracle's pipe name
    """
    identities = [
        server.Identity(raw=serde.serialize_public(key.public()), key=key),
        server.Identity(raw=cert_blob, key=key),
    ]
    # 128 bits from the OS CSPRNG. Unlike `session.pipe_name` this is not
    # recomputed by anyone so it can be random rather than derived, and a
    # collision with a live pipe is not a case worth retrying.
    name = pipe_name(secrets.token_hex(16))
    handle = _win32api.try_create_named_pipe(name, inheritable=True)
    if handle is None:
        raise exceptions.Error(f"Unable to create the connection oracle pipe {name}")
    try:
        spawn.spawn_subprocess(handle, key, identities, anchor, ttl, mode="connection")
    finally:
        # The child holds its own inherited copy; ours would otherwise keep the
        # pipe alive past the oracle's exit and leave `ssh` connecting to
        # nothing.
        _win32api.close_handle(handle)
    return name


def authorize(anchor: peercred.Anchor) -> collections.abc.Callable[[int], bool]:
    """Build the accept-time check the oracle subprocess runs on every peer."""

    def authorize(pipe_handle: int) -> bool:
        try:
            peer = peercred.peer_identity(pipe_handle)
        except (exceptions.Error, OSError):
            return False
        return peercred.same_process(peer, anchor) or peercred.is_descendant_of(peer.pid, anchor)

    return authorize
