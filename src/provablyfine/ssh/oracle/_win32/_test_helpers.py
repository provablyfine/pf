"""Child-process helpers for `test_win32.py`.

Underscore-prefixed so pytest doesn't collect it as a test module
"""

from __future__ import annotations

import hashlib
import os
import sys
import time

from ... import agent, exceptions
from . import peercred


def _shell_identity() -> None:
    """Print the login-shell anchor this process resolves to."""
    pid, creation_time = peercred.login_shell_identity()
    print(f"{pid} {creation_time}", flush=True)


def _sleep(pid_file: str) -> None:
    """Record our pid, then idle until killed.

    Used as an anchor whose lifetime the test controls, and as the leaf of a
    deliberately deep process chain.
    """
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    time.sleep(600)


def _list_identities(pipe_name: str) -> None:
    """Print a digest of every identity blob the oracle at `pipe_name` lists.

    The connection-key oracle's whole point is that its peer is a *descendant*
    of the anchor rather than the anchor itself, and a descendant is by
    definition not the test process -- so the check has to be made from a
    child.

    Digests of `identity.raw`, not fingerprints: a certificate embeds the very
    public key it certifies, so the bare-key identity and the certificate
    identity have *identical* ssh fingerprints and only the raw blobs tell them
    apart.

    Prints "REJECTED" on the failure an unauthorized peer gets, so the caller
    can tell a rejection from a crash.
    """
    try:
        client = agent.Client(pipe_name)
    except OSError as e:
        print(f"REJECTED {e}", flush=True)
        return
    try:
        for identity in client.list_identities():
            print(hashlib.sha256(identity.raw).hexdigest()[:16], flush=True)
    except (OSError, exceptions.Error) as e:
        print(f"REJECTED {e}", flush=True)
    finally:
        client.close()


def _list_when_ready(pid_file: str, name_file: str) -> None:
    """Announce our pid, wait to be told a pipe name, then list it.

    The connection oracle's name is random and is only chosen *after* its
    anchor exists, so a descendant of that anchor cannot be given the name on
    its command line -- it has to already be running, and be told later. The
    file is that channel.
    """
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with open(name_file) as f:
                name = f.read().strip()
            if name:
                _list_identities(name)
                return
        except OSError:
            pass
        time.sleep(0.05)
    print("REJECTED never told a pipe name", flush=True)


def main() -> None:
    mode = sys.argv[1]
    if mode == "shell-identity":
        _shell_identity()
    elif mode == "sleep":
        _sleep(sys.argv[2])
    elif mode == "list-when-ready":
        _list_when_ready(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit(f"unknown helper mode: {mode!r}")


if __name__ == "__main__":
    main()
