"""Single platform dispatch point for the registry's file lock."""

from __future__ import annotations

import sys

if sys.platform == "win32":
    from . import _filelock_win32 as _impl
else:
    from . import _filelock_posix as _impl

try_lock = _impl.try_lock
unlock = _impl.unlock

__all__ = ["try_lock", "unlock"]
