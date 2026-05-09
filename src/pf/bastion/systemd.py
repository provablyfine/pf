"""Helpers for systemd integration (sd_notify, socket activation)."""

from __future__ import annotations

import os
import socket

SD_LISTEN_FDS_START = 3


def notify(msg: str) -> None:
    """Send notification to systemd via NOTIFY_SOCKET (no-op if not set)."""
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return
    if notify_socket.startswith("@"):
        # abstract namespace socket
        addr = "\0" + notify_socket[1:]
    else:
        addr = notify_socket
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.sendto(msg.encode(), addr)


def listen_fds() -> list[socket.socket]:
    """Return sockets passed by systemd socket activation, or [] if none."""
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds_count = os.environ.get("LISTEN_FDS")
    if not listen_pid or not listen_fds_count:
        return []
    if int(listen_pid) != os.getpid():
        return []
    n = int(listen_fds_count)
    socks: list[socket.socket] = []
    for i in range(n):
        fd = SD_LISTEN_FDS_START + i
        # dup so caller owns the fd independently
        sock: socket.socket = socket.socket(fileno=os.dup(fd))
        socks.append(sock)
    return socks
