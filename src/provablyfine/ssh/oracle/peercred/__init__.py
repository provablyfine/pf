"""Kernel-verified peer-process identity for the oracle's UNIX-socket peers.

Pure, server-independent primitives, no socket-protocol knowledge -- just
"who is on the other end of this connection, and is it who we think it is."

Dispatches to `_linux.py` or `_darwin.py` below, which export identical
names for identical purposes -- see their module docstrings for the
platform-specific primitives each is built on. Any other platform gets
`_unsupported.py`, whose functions all raise a clear `exceptions.Error` when
actually called; `spawn.require_platform_supported()` is the real gate
callers hit first, but merely *importing* `provablyfine.ssh` -- which
happens on every platform -- must never itself crash.
"""

from __future__ import annotations

import select
import sys

if sys.platform == "linux":
    from . import _linux as _impl
elif sys.platform == "darwin":
    from . import _darwin as _impl
else:
    from . import _unsupported as _impl

Anchor = _impl.Anchor
PeerIdentity = _impl.PeerIdentity
anchor_extra_fds = _impl.anchor_extra_fds
anchor_spawn_token = _impl.anchor_spawn_token
close_anchor = _impl.close_anchor
close_peer_identity = _impl.close_peer_identity
is_descendant_of = _impl.is_descendant_of
open_anchor = _impl.open_anchor
parent_session_id = _impl.parent_session_id
parent_tty_dev = _impl.parent_tty_dev
peer_identity = _impl.peer_identity
peer_session_facts = _impl.peer_session_facts
process_starttime = _impl.process_starttime
reconstruct_anchor = _impl.reconstruct_anchor
same_process = _impl.same_process

__all__ = [
    "Anchor",
    "PeerIdentity",
    "anchor_extra_fds",
    "anchor_spawn_token",
    "close_anchor",
    "close_peer_identity",
    "is_alive",
    "is_descendant_of",
    "open_anchor",
    "parent_session_id",
    "parent_tty_dev",
    "peer_identity",
    "peer_session_facts",
    "process_starttime",
    "reconstruct_anchor",
    "same_process",
]


def is_alive(anchor: Anchor) -> bool:
    """True while the process pinned by `anchor` is still running.

    Identical on every supported platform: `anchor.fd` becomes readable
    (POLLIN) the instant its process exits, whether it's a Linux pidfd or a
    Darwin kqueue exit-watch (verified empirically) -- this is what lets the
    oracle's accept loop wait on both a TTL deadline and "has my anchor
    process died" without polling. Must stay a non-destructive peek: reading
    the exit event off a kqueue (unlike a pidfd) makes it stop reporting
    readable, i.e. would make a dead anchor look alive again.
    """
    readable, _, _ = select.select([anchor.fd], [], [], 0)
    return len(readable) == 0
