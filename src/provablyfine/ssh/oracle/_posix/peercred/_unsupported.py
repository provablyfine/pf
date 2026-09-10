"""Stub backend for any platform that is neither Linux nor macOS.

Every function here raises -- merely importing `provablyfine.ssh` must never
crash regardless of platform, but nothing in this package actually works
outside Linux/Darwin. `spawn.require_platform_supported()` is the real gate,
called at the top of every oracle entry point before any of these would run.
"""

from __future__ import annotations

import dataclasses
import socket

from .... import exceptions

_MESSAGE = "The peer-credential signing oracle only supports Linux and macOS"


@dataclasses.dataclass(frozen=True)
class Anchor:
    fd: int


@dataclasses.dataclass(frozen=True)
class PeerIdentity:
    pid: int


def peer_identity(_conn: socket.socket) -> PeerIdentity:
    raise exceptions.Error(_MESSAGE)


def close_peer_identity(_peer: PeerIdentity) -> None:
    raise exceptions.Error(_MESSAGE)


def same_process(_peer: PeerIdentity, _anchor: Anchor) -> bool:
    raise exceptions.Error(_MESSAGE)


def peer_session_facts(_conn: socket.socket, _peer: PeerIdentity) -> tuple[int | None, int | None]:
    raise exceptions.Error(_MESSAGE)


def parent_session_id(_pid: int) -> int | None:
    raise exceptions.Error(_MESSAGE)


def parent_tty_dev(_pid: int) -> int | None:
    raise exceptions.Error(_MESSAGE)


def parent_is_launcher() -> bool:
    return False


def is_descendant_of(_pid: int, _anchor: Anchor, *, max_depth: int = 64) -> bool:
    raise exceptions.Error(_MESSAGE)


def process_starttime(_pid: int) -> int:
    raise exceptions.Error(_MESSAGE)


def open_anchor(_pid: int) -> Anchor:
    raise exceptions.Error(_MESSAGE)


def close_anchor(_anchor: Anchor) -> None:
    raise exceptions.Error(_MESSAGE)


def anchor_extra_fds(_anchor: Anchor) -> tuple[int, ...]:
    raise exceptions.Error(_MESSAGE)


def anchor_spawn_token(_anchor: Anchor, _extra_fds: tuple[int, ...]) -> str:
    raise exceptions.Error(_MESSAGE)


def reconstruct_anchor(_token: str) -> Anchor:
    raise exceptions.Error(_MESSAGE)
