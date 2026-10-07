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
elif sys.platform == "win32":
    from . import win32


__all__ = ["apply", "base", "defaults", "is_privileged", "ops", "procs", "provider", "reload_sshd"]


def provider() -> base.Provider:
    if sys.platform == "linux":
        return linux.Linux()
    installed_pf = sys.executable if getattr(sys, "frozen", False) else None
    if sys.platform == "darwin":
        return darwin.Darwin(installed_pf)
    if sys.platform == "win32":
        return win32.Windows(installed_pf)
    raise pfc.exceptions.UI(f"This command is not supported on {sys.platform}")


def defaults() -> base.Defaults:
    if sys.platform == "win32":
        return win32.DEFAULTS
    return base.Defaults(
        host_keys_dir="/etc/ssh",
        ca_pub_path="/etc/ssh/pf_ca.pub",
        sshd_config_drop_in="/etc/ssh/sshd_config.d/10-pf.conf",
        auth_user="nobody",
    )


def is_privileged() -> bool:
    """Whether this process may change the system: root, or an elevated administrator on Windows."""
    if sys.platform == "win32":
        return win32.is_elevated()
    return os.geteuid() == 0


def apply(dry_run: bool, action: collections.abc.Callable[[ops.Ops], None]) -> None:
    if dry_run:
        recorder = ops.DryRunOps()
        action(recorder)
        # A console can be unable to show a character, such as on Windows with cp1252. A preview must not fail for that.
        encoding = sys.stdout.encoding or "utf-8"
        sys.stdout.write(recorder.describe().encode(encoding, errors="replace").decode(encoding))
        return
    if not is_privileged():
        if sys.platform == "win32":
            raise pfc.exceptions.UI(
                "host-init must run as an administrator. Open a terminal with Run as administrator."
            )
        raise pfc.exceptions.UI("host-init must run as root, for example: sudo /usr/bin/pf openssh host-init ...")
    action(ops.SystemOps())


def reload_sshd() -> None:
    """Make the SSH daemon read new host certificates, on platforms where that is needed.

    On macOS launchd starts a new sshd for every connection, so nothing is needed.
    On Windows sshd reads host certificates for every connection.
    """
    if sys.platform == "linux":
        linux.Linux().reload_sshd(ops.SystemOps())
