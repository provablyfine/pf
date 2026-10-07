"""The process table on Windows.

This reads Toolhelp snapshots. WMI would not do: a standard user cannot see the
processes that belong to SYSTEM, and the principals command runs as a standard
user below an sshd that belongs to SYSTEM. A snapshot lists every process.
"""

from __future__ import annotations

from .... import _w32 as w32
from .... import ssh
from . import procs

_FILETIME_UNIX_EPOCH = 116444736000000000


def _filetime_to_unix_seconds(ticks: int) -> int:
    return (ticks - _FILETIME_UNIX_EPOCH) // 10_000_000


class Win32Table:
    def snapshot(self) -> procs.Snapshot:
        return {
            entry.pid: procs.Proc(entry.pid, entry.parent_pid, entry.image_name) for entry in w32.process.snapshot()
        }

    def start_time(self, pid: int) -> int | None:
        # Ask for the least access. A standard user may not wait on a SYSTEM process.
        handle = w32.process.open_process(pid, w32.raw.PROCESS_QUERY_LIMITED_INFORMATION)
        if handle is None:
            return None
        try:
            return _filetime_to_unix_seconds(w32.process.process_creation_time(handle))
        except ssh.exceptions.Error:
            return None
        finally:
            w32.process.close_handle(handle)

    def send_signal(self, pid: int, *, force: bool) -> None:
        """End the process. Windows has no gentle request, so `force` makes no difference."""
        w32.process.terminate(pid)
