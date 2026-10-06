"""host-init: set up the local SSH daemon to trust pf.

Each platform has a provider. `apply` runs a provider action for real, as
root, or as a dry run that only prints what it would do.
"""

from __future__ import annotations

import collections.abc
import os
import sys

import provablyfine_client as pfc

from . import base, ops, procs

if sys.platform == "linux":
    from . import linux
elif sys.platform == "darwin":
    from . import darwin


__all__ = ["apply", "base", "ops", "procs", "provider", "reload_sshd"]


def provider() -> base.Provider:
    if sys.platform == "linux":
        return linux.Linux()
    if sys.platform == "darwin":
        return darwin.Darwin(sys.executable if getattr(sys, "frozen", False) else None)
    raise pfc.exceptions.UI("This command is not supported on native Windows")


def apply(dry_run: bool, action: collections.abc.Callable[[ops.Ops], None]) -> None:
    if dry_run:
        recorder = ops.DryRunOps()
        action(recorder)
        sys.stdout.write(recorder.describe())
        return
    if os.geteuid() != 0:
        raise pfc.exceptions.UI("host-init must run as root, for example: sudo /usr/bin/pf openssh host-init ...")
    action(ops.SystemOps())


def reload_sshd() -> None:
    """Make the SSH daemon read new host certificates, on platforms where that is needed.

    On macOS launchd starts a new sshd for every connection, so nothing is needed.
    """
    if sys.platform == "linux":
        linux.Linux().reload_sshd(ops.SystemOps())
