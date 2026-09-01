# Regenerate with (xdist disabled: interactive pty-driving tests must not
# run under parallel workers):
#   PF_RECORD_TOUR=1 uv run pytest tests/test_tui_tour.py -n0 -v
import json
import os
import sys

import pytest

from . import tui_support, tui_tour

pytestmark = pytest.mark.skipif(
    not os.environ.get("PF_RECORD_TOUR"),
    reason="tour recording only runs when explicitly requested (PF_RECORD_TOUR=1)",
)

_ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "assets"))
_WIDTH = 100
_HEIGHT = 30


def _pfat_env(tmpdir: str, ssh_agent) -> dict[str, str]:
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
    return {**os.environ, "PATH": f"{scripts}:{os.environ['PATH']}", "SSH_AUTH_SOCK": ssh_agent.socket}


def _assert_valid_cast(path: str) -> None:
    with open(path) as f:
        header = json.loads(f.readline())
    assert header["version"] == 2
    assert header["width"] == _WIDTH
    assert header["height"] == _HEIGHT


def test_record_quick_tour(api, ssh_agent, tmp_path):
    """Browse-only tour, pre-authenticated (boots straight into the
    Identities list): no login flow, no creation. Runs the TuiApp directly
    (bypassing SetupApp/ReloginScreen),
    same as the existing test_tui.py tests do via TuiApp(auth).run_test()."""
    tmpdir = str(tmp_path)
    tui_support._setup(api, tmpdir, ssh_agent)
    tui_support._seed_named_identities(api, tmpdir, ssh_agent, ["alice", "bob", "carol"])
    config_file = os.path.join(tmpdir, "config.json")

    run_home = os.path.join(os.path.dirname(__file__), "tui_tour", "run_home.py")
    argv = [sys.executable, run_home, config_file]
    env = dict(os.environ)

    os.makedirs(_ASSETS_DIR, exist_ok=True)
    output = os.path.join(_ASSETS_DIR, "tui-tour-quick.cast")

    with tui_tour.PtyRecorder(argv, env, width=_WIDTH, height=_HEIGHT) as rec:
        tui_tour.run_scenario(rec, tui_tour.QUICK_TOUR)
        rec.write_cast(output)

    _assert_valid_cast(output)


def test_record_thorough_tour(api, ssh_agent, tmp_path):
    """Full tour: real pfat CLI entrypoint (Setup/Relogin login flow), then
    every resource section, each creating its own demo data live."""
    tmpdir = str(tmp_path)
    tui_support._setup(api, tmpdir, ssh_agent)
    config_file = os.path.join(tmpdir, "config.json")

    argv = ["pfat", "-c", config_file]
    env = _pfat_env(tmpdir, ssh_agent)

    os.makedirs(_ASSETS_DIR, exist_ok=True)
    output = os.path.join(_ASSETS_DIR, "tui-tour-thorough.cast")

    with tui_tour.PtyRecorder(argv, env, width=_WIDTH, height=_HEIGHT) as rec:
        tui_tour.run_scenario(rec, tui_tour.THOROUGH_TOUR)
        rec.write_cast(output)

    _assert_valid_cast(output)
