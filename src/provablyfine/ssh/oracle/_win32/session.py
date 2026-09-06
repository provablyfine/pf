"""Session-key oracle: the only oracle model on Windows.

Its legitimate callers are separate, not-yet-existing future `pf`/`pfa`
invocations over the key's whole TTL (~1800s), so there is no single process to
pin. Instead, at `pf login` time two kernel-verified facts about the calling
shell are recorded, and every later caller is checked against both:

1. A mandatory anchor pinned to the login shell itself. A caller
   must *be* that exact process or a kernel-verified descendant of it (walked
   with pinned handles, not raw pid comparison).
2. Optionally, the shell's Windows session id, when readable.

The trust model to compare this against is real ssh-agent's, where any process
running as the same user can ask the agent to sign.
"""

from __future__ import annotations

import collections.abc
import hashlib
import logging
import time

from .... import jwk
from ... import exceptions, serde
from . import _win32api, peercred, server, spawn

logger = logging.getLogger(__name__)

_NEW_LOGIN_TIMEOUT_SECONDS = 5.0


def _digest(pid: int, creation_time: int) -> str:
    return hashlib.sha256(f"{pid}:{creation_time}".encode()).hexdigest()[:16]


def pipe_name(pid: int, creation_time: int) -> str:
    """The oracle's pipe name, derived from its anchor.

    Only requirement is determinism -- a later `pf` has to recompute it with no
    shared state. It is not a secret, and does not need to be: the access
    control is the peer-credential check in `authorize()`, not the name.

    A squatter who created the pipe first is not a real exposure either.
    `create_named_pipe` uses FILE_FLAG_FIRST_PIPE_INSTANCE, so `pf login`
    fails loudly rather than sharing the name. To be *sent* a signing
    request an impostor would have to list back our session public key, whose
    fingerprint lives in the user's own config file.
    """
    return f"\\\\.\\pipe\\pf-session-oracle-{_digest(pid, creation_time)}"


def _new_login_event_name(pid: int, creation_time: int) -> str:
    # A bare name, so it lands in the per-Windows-session object namespace --
    # which is exactly the scope wanted, and is not a path: the
    # `\BaseNamedObjects\...` form is not accepted by CreateEventW.
    return f"pf-session-oracle-{_digest(pid, creation_time)}-new-login"


def current_socket_path() -> str:
    """Recompute this invocation's oracle name from its own login shell.

    Used by later `pf`/`pfa` invocations in the same shell to find the oracle
    `pf login` spawned there. Named "socket path" because its callers are
    cross-platform; on Windows the string is a named pipe, not a path.
    """
    return pipe_name(*peercred.login_shell_identity())


def spawn_oracle(key: jwk.Private, ttl: float = 1800) -> str:
    """Spawn a session-key oracle bound to the calling process's login shell.

    Returns the oracle's pipe name.
    """
    return _spawn(key, ttl, peercred.login_shell_identity()[0])


def _spawn(key: jwk.Private, ttl: float, anchor_pid: int) -> str:
    """Spawn an oracle anchored on `anchor_pid`.

    Split out from `spawn_oracle` so tests can anchor on a process they created
    rather than on whatever happened to launch pytest.
    """
    anchor = peercred.open_anchor(anchor_pid)
    try:
        name = pipe_name(anchor.pid, anchor.creation_time)
        event_name = _new_login_event_name(anchor.pid, anchor.creation_time)
        handle = _create_pipe_on_new_login(name, event_name)
    except BaseException:
        peercred.close_anchor(anchor)
        raise
    identities = [server.Identity(raw=serde.serialize_public(key.public()), key=key)]
    try:
        spawn.spawn_subprocess(
            handle,
            key,
            identities,
            anchor,
            ttl,
            mode="session",
            event_name=event_name,
            session_id=peercred.session_id(anchor.pid),
        )
    finally:
        _win32api.close_handle(handle)
        peercred.close_anchor(anchor)
    return name


def _create_pipe_on_new_login(name: str, event_name: str) -> int:
    """Create the listening pipe, asking any predecessor to stand down first."""
    deadline = time.monotonic() + _NEW_LOGIN_TIMEOUT_SECONDS
    announced = False
    while True:
        handle = _win32api.try_create_named_pipe(name, inheritable=True)
        if handle is not None:
            return handle
        if time.monotonic() >= deadline:
            raise exceptions.Error(
                f"An existing session oracle is still holding {name} after "
                f"{_NEW_LOGIN_TIMEOUT_SECONDS:.0f}s; it did not respond to a new login"
            )
        if not announced:
            logger.debug("A newer login is waiting on an existing session oracle")
            announced = True
        predecessor = _win32api.open_event(event_name)
        if predecessor is not None:
            try:
                _win32api.set_event(predecessor)
            finally:
                _win32api.close_handle(predecessor)
        time.sleep(0.05)


def authorize(anchor: peercred.Anchor, session_id: int | None) -> collections.abc.Callable[[int], bool]:
    """Build the accept-time check the oracle subprocess runs on every peer.

    Reconstructed by `_runner.py` inside the child from the same anchor passed
    down through argv -- not called by `_spawn` above, since a spawned child is
    a fresh interpreter and no Python closure survives into it.
    """

    def authorize(pipe_handle: int) -> bool:
        try:
            peer = peercred.peer_identity(pipe_handle)
        except (exceptions.Error, OSError):
            return False
        if not (peercred.same_process(peer, anchor) or peercred.is_descendant_of(peer.pid, anchor)):
            return False
        return session_id is None or peercred.session_id(peer.pid) == session_id

    return authorize
