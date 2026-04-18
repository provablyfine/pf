from __future__ import annotations

import asyncio
import os
import subprocess
import typing


from . import base


def _supports_osc52() -> bool:
    """Return True if the terminal is known to support OSC52 clipboard writes."""
    if os.environ.get("KITTY_WINDOW_ID"):
        return True
    if os.environ.get("ITERM_SESSION_ID"):
        return True
    term_program = os.environ.get("TERM_PROGRAM", "")
    if term_program in ("WezTerm", "iTerm.app"):
        return True
    term = os.environ.get("TERM", "")
    if "kitty" in term or "foot" in term:
        return True
    return False


def _copy_via_subprocess(text: str) -> None:
    if os.environ.get("WAYLAND_DISPLAY"):
        subprocess.run(["/usr/bin/wl-copy"], input=text.encode(), check=True)
        return
    if os.environ.get("DISPLAY"):
        try:
            subprocess.run(["/usr/bin/xsel", "-bi"], input=text.encode(), check=True)
            return
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        subprocess.run(["/usr/bin/xclip", "-selection", "clipboard"], input=text.encode(), check=True)
        return
    raise RuntimeError("No clipboard mechanism available")


async def copy(app: base.App, text: str) -> None:
    if _supports_osc52():
        app.copy_to_clipboard(text)
        return
    await asyncio.to_thread(_copy_via_subprocess, text)
