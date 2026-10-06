"""Steps shared by the platform providers."""

from __future__ import annotations

import re
import typing

import provablyfine_client as pfc

from .... import jwk
from . import ops

# Values end up in sshd and service configuration files, where a space or a
# newline would start another setting.
_PLAIN = re.compile(r"[A-Za-z0-9_./@%+=,:-]+")


def require_plain(value: str, what: str) -> str:
    if _PLAIN.fullmatch(value) is None:
        raise pfc.exceptions.UI(
            f"{what} contains characters that cannot be written safely to a configuration file: {value!r}"
        )
    return value


def new_account_key_pem() -> bytes:
    return jwk.Private.generate_ed25519().to_pem()


def conflicting_directive(o: ops.Ops, paths: typing.Iterable[str], names: typing.Iterable[str]) -> str | None:
    """The first directive in `names` that an existing sshd configuration file already sets."""
    pattern = re.compile(r"^(" + "|".join(re.escape(name) for name in names) + r")")
    for path in paths:
        text = o.read_text(path)
        if text is None:
            continue
        for line in text.splitlines():
            found = pattern.match(line)
            if found is not None:
                return found.group(1)
    return None


def append_block(text: str, block: str) -> str:
    if text and not text.endswith("\n"):
        text += "\n"
    return text + block


def remove_block(text: str, begin: str, end: str) -> str:
    """Drop every line from a `begin` line to the next `end` line, both included."""
    kept: list[str] = []
    inside = False
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\n")
        if not inside and stripped == begin:
            inside = True
            continue
        if inside:
            if stripped == end:
                inside = False
            continue
        kept.append(line)
    return "".join(kept)
