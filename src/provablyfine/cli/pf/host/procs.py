"""Look at the process table, to find and end an SSH session.

The functions read `ps`, so they work on macOS and on Linux.
"""

from __future__ import annotations

import dataclasses
import os
import re
import signal
import subprocess
import time
import typing


@dataclasses.dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    command: str


Snapshot = dict[int, Proc]

# The title of the per-connection process that runs as root. OpenSSH 9.8 and
# later call it "sshd-session: user [priv]". Older versions call it "sshd: user [priv]".
_MONITOR = re.compile(r"sshd(-session)?: .* \[priv\]")


def is_sshd_monitor(proc: Proc) -> bool:
    return _MONITOR.fullmatch(proc.command.strip()) is not None


def parse_ps(output: str) -> Snapshot:
    table: Snapshot = {}
    for line in output.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        table[pid] = Proc(pid, ppid, parts[2] if len(parts) == 3 else "")
    return table


def parse_start_time(text: str) -> int | None:
    """Parse the `lstart` column of ps, for example "Tue Oct  6 17:52:00 2026"."""
    try:
        return int(time.mktime(time.strptime(text.strip(), "%a %b %d %H:%M:%S %Y")))
    except ValueError:
        return None


def ancestors(table: Snapshot, pid: int) -> list[Proc]:
    """The parents of `pid`, nearest first."""
    found: list[Proc] = []
    seen = {pid}
    current = table.get(pid)
    while current is not None and current.ppid > 0 and current.ppid not in seen:
        parent = table.get(current.ppid)
        if parent is None:
            break
        found.append(parent)
        seen.add(parent.pid)
        current = parent
    return found


def find_ancestor(table: Snapshot, pid: int, predicate: typing.Callable[[Proc], bool]) -> Proc | None:
    for proc in ancestors(table, pid):
        if predicate(proc):
            return proc
    return None


def descendants(table: Snapshot, pid: int) -> list[int]:
    """Every process below `pid`, found by following parents, nearest first."""
    children: dict[int, list[int]] = {}
    for proc in table.values():
        children.setdefault(proc.ppid, []).append(proc.pid)
    found: list[int] = []
    queue = [pid]
    while queue:
        for child in sorted(children.get(queue.pop(0), [])):
            if child != pid and child not in found:
                found.append(child)
                queue.append(child)
    return found


class ProcessTable(typing.Protocol):
    def snapshot(self) -> Snapshot: ...

    def start_time(self, pid: int) -> int | None:
        """When the process started, in whole seconds, or None if it is gone."""

    def send_signal(self, pid: int, number: int) -> None: ...


def _ps(*arguments: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["ps", *arguments],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={**os.environ, "LC_ALL": "C"},
    )
    return result.stdout


class PsTable:
    def snapshot(self) -> Snapshot:
        return parse_ps(_ps("-axo", "pid=,ppid=,command="))

    def start_time(self, pid: int) -> int | None:
        return parse_start_time(_ps("-o", "lstart=", "-p", str(pid)))

    def send_signal(self, pid: int, number: int = signal.SIGTERM) -> None:
        try:
            os.kill(pid, number)
        except ProcessLookupError:
            pass
