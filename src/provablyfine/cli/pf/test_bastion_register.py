from __future__ import annotations

import argparse

import provablyfine_client as pfc
import pytest

from . import bastion_cli, host


def test_register_refuses_to_run_privileged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host, "is_privileged", lambda: True)
    with pytest.raises(pfc.exceptions.UI, match="must not run as root"):
        bastion_cli._register_function(argparse.Namespace())  # pyright: ignore[reportPrivateUsage]
