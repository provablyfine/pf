import asyncio
import os
import subprocess
import typing

if typing.TYPE_CHECKING:
    import textual.app


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
    print('d')
    if os.environ.get("WAYLAND_DISPLAY"):
        print('e')
        subprocess.run(["wl-copy"], input=text.encode(), check=True)
        return
    print('f')
    if os.environ.get("DISPLAY"):
        print('g')
        try:
            subprocess.run(["xsel", "-bi"], input=text.encode(), check=True)
            return
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True)
        return
    raise RuntimeError("No clipboard mechanism available")


async def copy(app: "textual.app.App[object]", text: str) -> None:
    print('a')
    if _supports_osc52():
        print('b')
        app.copy_to_clipboard(text)
        return
    print('c')
    await asyncio.to_thread(_copy_via_subprocess, text)
