import fcntl
import json
import os
import pty
import select
import signal
import struct
import termios
import time

import pyte

# Only the keys the tour scenarios actually press. Anything not listed here is
# sent as literal text, one os.write() per call to send().
_KEYS: dict[str, bytes] = {
    "up": b"\x1b[A",
    "down": b"\x1b[B",
    "right": b"\x1b[C",
    "left": b"\x1b[D",
    "enter": b"\r",
    "escape": b"\x1b",
    "tab": b"\t",
    "space": b" ",
    "backspace": b"\x7f",
    "ctrl+s": b"\x13",
}


class TourTimeoutError(Exception):
    pass


def _set_winsize(fd: int, width: int, height: int) -> None:
    winsize = struct.pack("HHHH", height, width, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)


class PtyRecorder:
    """Drives a TUI program in a real pty and records its output as an
    asciinema v2 cast, advancing on rendered screen content rather than
    fixed sleeps or raw-ANSI pattern matching."""

    def __init__(self, argv: list[str], env: dict[str, str], width: int = 100, height: int = 30) -> None:
        self._width = width
        self._height = height
        self._events: list[tuple[float, bytes]] = []
        self._markers: list[tuple[float, str]] = []
        self._screen = pyte.Screen(width, height)
        self._stream = pyte.Stream(self._screen)
        self._start = time.monotonic()

        pid, master_fd = pty.fork()
        if pid == 0:
            try:
                os.execvpe(argv[0], argv, env)
            finally:
                os._exit(127)

        self._pid = pid
        self._master_fd = master_fd
        _set_winsize(master_fd, width, height)

    def __enter__(self) -> "PtyRecorder":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _drain(self, timeout: float) -> bool:
        ready, _, _ = select.select([self._master_fd], [], [], max(timeout, 0.0))
        if not ready:
            return False
        try:
            data = os.read(self._master_fd, 65536)
        except OSError:
            return False
        if not data:
            return False
        elapsed = time.monotonic() - self._start
        self._events.append((elapsed, data))
        self._stream.feed(data.decode("utf-8", errors="replace"))
        return True

    def wait_for(self, text: str, timeout: float = 5.0, settle: float = 0.4) -> None:
        deadline = time.monotonic() + timeout
        matched = False
        while time.monotonic() < deadline:
            if any(text in line for line in self._screen.display):
                matched = True
                break
            self._drain(timeout=min(0.2, deadline - time.monotonic()))
        if not matched and any(text in line for line in self._screen.display):
            matched = True
        if not matched:
            raise TourTimeoutError(f"timed out waiting for {text!r}; screen:\n" + "\n".join(self._screen.display))
        # A match can land mid-transition (e.g. a screen push still settling
        # focus after its first paint): keep draining until output goes quiet
        # so the next send() isn't racing an in-flight render.
        settle_deadline = time.monotonic() + settle
        while time.monotonic() < settle_deadline:
            if not self._drain(timeout=max(0.0, settle_deadline - time.monotonic())):
                break

    def mark(self, label: str) -> None:
        """Record a chapter marker at the current point in the recording,
        rendered by asciinema-player as a clickable, timestamped label."""
        self._markers.append((time.monotonic() - self._start, label))

    def send(self, *keys: str) -> None:
        for key in keys:
            data = _KEYS.get(key, key.encode())
            os.write(self._master_fd, data)
            self._drain(timeout=0.05)  # give the app a moment to react, keep draining

    def close(self, timeout: float = 5.0) -> None:
        os.kill(self._pid, signal.SIGTERM)
        deadline = time.monotonic() + timeout
        reaped = False
        while time.monotonic() < deadline:
            reaped_pid, _ = os.waitpid(self._pid, os.WNOHANG)
            if reaped_pid == self._pid:
                reaped = True
                break
            time.sleep(0.05)
        if not reaped:
            os.kill(self._pid, signal.SIGKILL)
            os.waitpid(self._pid, 0)
        os.close(self._master_fd)

    def write_cast(self, path: str, max_gap: float = 1.2) -> None:
        """Serialize the recorded events (output and markers, merged in
        chronological order) as an asciinema v2 cast. Any single inter-event
        gap is capped at max_gap so a slow API call during recording doesn't
        produce dead air in playback."""
        header = {
            "version": 2,
            "width": self._width,
            "height": self._height,
            "timestamp": int(time.time()),
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        }
        events: list[tuple[float, str, str]] = [
            (elapsed, "o", data.decode("utf-8", errors="replace")) for elapsed, data in self._events
        ]
        events += [(elapsed, "m", label) for elapsed, label in self._markers]
        events.sort(key=lambda event: event[0])

        with open(path, "w") as f:
            f.write(json.dumps(header) + "\n")
            prev_elapsed = 0.0
            cursor = 0.0
            for elapsed, kind, payload in events:
                gap = min(elapsed - prev_elapsed, max_gap)
                cursor += max(gap, 0.0)
                prev_elapsed = elapsed
                row = [round(cursor, 6), kind, payload]
                f.write(json.dumps(row) + "\n")
