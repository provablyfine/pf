from __future__ import annotations

import io

import pytest

from . import apply, ops


def test_a_dry_run_does_not_fail_on_a_console_that_cannot_show_a_character(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = io.BytesIO()
    console = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr("sys.stdout", console)

    def action(o: ops.Ops) -> None:
        o.write_file("/etc/example", "arrow → done\n", 0o644)

    apply(True, action)
    console.flush()
    assert b"arrow ? done" in raw.getvalue()
