from __future__ import annotations

import pytest

from . import ssh_cli


@pytest.mark.parametrize(
    "platform,open_quote,close_quote",
    [
        ("linux", "'", "'"),
        ("win32", '"', '"'),
    ],
)
def test_quote_proxy_command_escapes_space_and_percent(
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    open_quote: str,
    close_quote: str,
) -> None:
    monkeypatch.setattr(ssh_cli.sys, "platform", platform)
    argv = [
        "pf",
        "-c",
        "C:/Users/a b/pf%config.json",
        "bastion",
        "connect",
        "--url=http://x",
        "--hostname=host",
        "--connection-id=abc",
    ]
    quoted = ssh_cli._quote_proxy_command(argv)
    assert f"{open_quote}C:/Users/a b/pf%%config.json{close_quote}" in quoted
    assert "%" not in quoted.replace("%%", "")


def test_quote_proxy_command_escapes_trailing_backslash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssh_cli.sys, "platform", "win32")
    quoted = ssh_cli._quote_proxy_command(["pf", "-c", "C:\\Users\\a b\\", "bastion"])
    assert quoted == 'pf -c "C:\\Users\\a b\\\\" bastion'
