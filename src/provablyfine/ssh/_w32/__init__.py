"""The shared low-level Win32 layer, used by both the ssh-agent client and the
signing oracle.

Organized by OS domain over a single raw ctypes surface:

- `raw`: DLL handles, structures, constants, and prototypes, named for the
  Win32 functions they wrap.
- `errors`: last-error formatting/raising and WER suppression.
- `process`: process handles -- open, close, creation time, image path, parent,
  and an exit-watch.
- `security`: tokens and SIDs (user and logon), and SDDL-to-`SECURITY_ATTRIBUTES`
  mechanics.
- `pipe`: named and anonymous pipes -- create, connect, byte I/O, and the
  kernel's record of the peer on each end.
- `event`: named events and handle waits.
- `spawn`: detached `CreateProcessW` with an explicit handle list.

Nothing here knows about the oracle's trust model; policy lives with callers,
which pass their DACLs and handle lists in. Importing this module only happens
under `sys.platform == "win32"`, so the `WinDLL` loads never run elsewhere.
"""

from __future__ import annotations

from . import errors, event, pipe, process, raw, security, spawn

__all__ = ["errors", "event", "pipe", "process", "raw", "security", "spawn"]
