"""Mandatory byte-range lock on Windows.

The kernel drops the lock when the owning process dies, however it dies.
The first byte is locked, even though the lock file stays empty.
"""

import msvcrt
import os


def try_lock(fd: int) -> bool:
    """Take the lock on `fd` without waiting. Returns False if someone else holds it."""
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except PermissionError:
        return False
    return True


def unlock(fd: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
