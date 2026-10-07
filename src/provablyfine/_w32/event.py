"""Named events and handle waits."""

from __future__ import annotations

import ctypes
import ctypes.wintypes

from .. import ssh
from . import errors, raw


def create_event(name: str) -> int:
    """A named, manual-reset event.

    Manual-reset because the watchdog waits on it once and must see it stay
    signaled. Note `CreateEventW` on an existing name *opens* that event rather
    than making a new one. Callers must `reset_event()` immediately after, or
    a predecessor's still-signaled event fires the new watchdog instantly.
    """
    handle = raw.k32.CreateEventW(None, True, False, name)
    if not handle:
        errors.raise_last_error(f"CreateEventW({name})")
    return handle


def open_event(name: str) -> int | None:
    """Open an existing named event, or None if there is no such event."""
    handle = raw.k32.OpenEventW(raw.EVENT_MODIFY_STATE | raw.SYNCHRONIZE, False, name)
    return None if not handle else handle


def set_event(handle: int) -> None:
    if not raw.k32.SetEvent(handle):
        errors.raise_last_error("SetEvent")


def reset_event(handle: int) -> None:
    if not raw.k32.ResetEvent(handle):
        errors.raise_last_error("ResetEvent")


def wait_for_single_object(handle: int, timeout_ms: int) -> int:
    result = raw.k32.WaitForSingleObject(handle, timeout_ms)
    if result == raw.WAIT_FAILED:
        errors.raise_last_error("WaitForSingleObject")
    return int(result)


def wait_for_any(handles: tuple[int, ...], timeout_ms: int) -> int | None:
    """Wait until any of `handles` is signaled; return its index, or None on
    timeout."""
    array = (ctypes.wintypes.HANDLE * len(handles))(*handles)
    result = raw.k32.WaitForMultipleObjects(len(handles), array, False, timeout_ms)
    if result == raw.WAIT_TIMEOUT:
        return None
    if result == raw.WAIT_FAILED:
        errors.raise_last_error("WaitForMultipleObjects")
    index = int(result) - raw.WAIT_OBJECT_0
    if not 0 <= index < len(handles):
        raise ssh.exceptions.Error(f"WaitForMultipleObjects returned an unexpected result: {result}")
    return index
