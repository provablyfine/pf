"""A `pf` started below a nested shell still reaches the login shell's oracle.

`pf login` binds the session oracle to the shell that ran it. Here that shell
is an outer `cmd.exe`. The command that needs the oracle runs in an inner
`cmd.exe`, so its closest shell is not the one that logged in.

Child output goes to files, never pipes.
"""

import os
import subprocess
import sys

import pytest

from . import cli as cli_support


@pytest.mark.skipif(sys.platform != "win32", reason="tests the Windows oracle lookup")
def test_pf_below_a_nested_shell_finds_the_oracle(api, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    cli = cli_support.Cli(work)
    cli.keygen("account")
    cli.run(
        "pfa",
        "-c",
        "config.json",
        "initialize",
        f"http://127.0.0.1:{api.port}/pf/t/00000000-0000-0000-0000-000000000001/directory",
        "--key",
        "account",
    )

    (work / "inner.bat").write_text("@echo off\r\npfa -c config.json auth list -q\r\n")
    (work / "outer.bat").write_text(
        "@echo off\r\n"
        "pfa -c config.json login || exit /b 1\r\n"
        "cmd.exe /c inner.bat > inner.out 2> inner.err\r\n"
        "exit /b %ERRORLEVEL%\r\n"
    )
    env = dict(os.environ)
    env["PATH"] = os.path.dirname(sys.executable) + os.pathsep + env["PATH"]
    with open(work / "outer.out", "wb") as out, open(work / "outer.err", "wb") as err:
        result = subprocess.run(
            ["cmd.exe", "/c", "outer.bat"],
            cwd=work,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            timeout=120,
        )
    inner_err = (work / "inner.err").read_text()
    assert result.returncode == 0, inner_err + (work / "outer.err").read_text()
    assert (work / "inner.out").read_text().strip() == "1"
