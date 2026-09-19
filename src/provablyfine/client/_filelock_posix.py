"""Advisory whole-file lock on POSIX.

The kernel drops the lock when the owning process dies, however it dies.
"""

import fcntl


def try_lock(fd: int) -> bool:
    """Take the lock on `fd` without waiting. Returns False if someone else holds it."""
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    return True


def unlock(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
