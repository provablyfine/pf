import pytest

from . import clipboard


def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("KITTY_WINDOW_ID", "ITERM_SESSION_ID", "TERM_PROGRAM", "TERM"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize(
    "env_var, value",
    [
        ("KITTY_WINDOW_ID", "1"),
        ("ITERM_SESSION_ID", "abc"),
        ("TERM_PROGRAM", "WezTerm"),
        ("TERM_PROGRAM", "iTerm.app"),
        ("TERM", "kitty"),
        ("TERM", "foot-extra"),
    ],
)
def test_supports_osc52_true(monkeypatch: pytest.MonkeyPatch, env_var: str, value: str) -> None:
    _clean_env(monkeypatch)
    monkeypatch.setenv(env_var, value)
    assert clipboard._supports_osc52() is True


def test_supports_osc52_false(monkeypatch: pytest.MonkeyPatch) -> None:
    _clean_env(monkeypatch)
    assert clipboard._supports_osc52() is False
