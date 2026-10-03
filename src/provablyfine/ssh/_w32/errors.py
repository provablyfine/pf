"""Win32 error reporting and crash-dump suppression."""

from __future__ import annotations

import ctypes
import typing

from .. import exceptions
from . import raw


def last_error_message(prefix: str) -> str:
    code = ctypes.get_last_error()
    return f"{prefix}: [{code}] {ctypes.FormatError(code)}"


def raise_last_error(prefix: str) -> typing.NoReturn:
    raise exceptions.Error(last_error_message(prefix))


def disable_wer_reporting() -> bool:
    """Keep WerFault out of this process, so a crash is not the seed for a
    user-readable dump (HKCU `LocalDumps` included). Best-effort by design:
    `_runner.main()`'s never-crash wrapper is the primary defense and this is
    the belt behind it, so a WER API that is absent on some Windows revision
    must not take login down with it."""
    sdds = raw.WER_FAULT_REP_DISABLE | raw.WER_DEBUG_INFO_DISABLE | raw.WER_UI_DISABLE
    for dll_name in ("wer", "advapi32"):
        try:
            dll = ctypes.WinDLL(dll_name)
        except OSError:
            continue
        try:
            return bool(dll.WerSetFlags(sdds))
        except (AttributeError, OSError):
            continue
    return False
