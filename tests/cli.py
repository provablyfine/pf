"""Driving `pf` and `pfa` from pytest, without a shell.

This is the pytest-native replacement for cram plus `tests/fixture.sh`. Cram
works well on Linux and is a dead end on Windows: it needs a POSIX shell
and everything that comes with it.

The one rule that is not obvious: child output goes to files, never pipes.

Everything here is platform-neutral on purpose.
"""

from __future__ import annotations

import contextlib
import itertools
import os
import os.path
import pathlib
import shutil
import subprocess
import sys

_counter = itertools.count()

_SYSTEM32_OPENSSH = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "OpenSSH")


def openssh_binary(name: str) -> str | None:
    """Locate an OpenSSH tool, preferring the native Windows build."""
    if sys.platform == "win32":
        native = os.path.join(_SYSTEM32_OPENSSH, f"{name}.exe")
        if os.path.exists(native):
            return native
    return shutil.which(name)


class CommandError(AssertionError):
    """A CLI invocation that failed, carrying enough context to debug it.

    cram compared whole-file output and reported a diff; here the assertion has
    to carry the command, the exit code and both streams itself, or a failure
    in a fixture step is unreadable.
    """

    def __init__(self, argv: list[str], returncode: int, stdout: str, stderr: str) -> None:
        super().__init__(
            f"command failed with exit {returncode}: {' '.join(argv)}\n"
            f"--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        )
        self.argv = argv
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class Cli:
    """Runs `pf`/`pfa` in a scratch directory, the way a cram script would.

    `workdir` stands in for cram's per-test temp directory: config files and
    generated keys are written there with relative names, exactly as the `.t`
    files do.
    """

    def __init__(self, workdir: pathlib.Path) -> None:
        self.workdir = workdir
        self._io = workdir / ".io"
        self._io.mkdir(exist_ok=True)

    def _binary(self, name: str) -> str:
        candidate = os.path.join(os.path.dirname(sys.executable), name)
        for path in (candidate, f"{candidate}.exe"):
            if os.path.exists(path):
                return path
        found = shutil.which(name)
        assert found is not None, f"{name} not found next to {sys.executable} nor on PATH"
        return found

    def popen(self, *args: str, stdin: str | None = None) -> tuple[subprocess.Popen[bytes], pathlib.Path]:
        """Start a command without waiting. Returns it and its stdout path."""
        argv = [self._binary(args[0]), *args[1:]]
        prefix = self._io / f"{next(_counter):03d}-{args[0]}"
        out_path = prefix.with_suffix(".out")
        err_path = prefix.with_suffix(".err")
        in_path = prefix.with_suffix(".in")
        if stdin is not None:
            in_path.write_text(stdin)
        # The files are closed here, not left to the child: Popen dups them, so
        # the child keeps working, while the parent does not accumulate a
        # descriptor per command for the life of the test.
        with contextlib.ExitStack() as handles:
            stdin_file = handles.enter_context(open(in_path, "rb")) if stdin is not None else subprocess.DEVNULL
            popen = subprocess.Popen(
                argv,
                cwd=self.workdir,
                stdin=stdin_file,
                stdout=handles.enter_context(open(out_path, "wb")),
                stderr=handles.enter_context(open(err_path, "wb")),
            )
        return popen, out_path

    def run(self, *args: str, stdin: str | None = None, check: bool = True) -> str:
        """Run to completion and return stdout. Raises `CommandError` on failure.

        `stdin` replaces the shell pipelines in the `.t` files, e.g.
        `pfa grant ssh ... | pfa role grant --add`.
        """
        popen, out_path = self.popen(*args, stdin=stdin)
        returncode = popen.wait()
        stdout = out_path.read_text()
        stderr = out_path.with_suffix(".err").read_text()
        if check and returncode != 0:
            raise CommandError([args[0], *args[1:]], returncode, stdout, stderr)
        return stdout

    def status(self, *args: str, stdin: str | None = None) -> tuple[int, str]:
        """Exit code and stdout, for the cases a `.t` asserted `[2]` on."""
        popen, out_path = self.popen(*args, stdin=stdin)
        returncode = popen.wait()
        return returncode, out_path.read_text()

    def keygen(self, name: str) -> pathlib.Path:
        """`ssh-keygen -t ed25519 -f <name> -N ""`, as the `.t` files do.

        Real ssh-keygen rather than `jwk.Private.generate_ed25519()` so the
        keys under test are the ones a user would actually have.
        """
        keygen = openssh_binary("ssh-keygen")
        assert keygen is not None, "ssh-keygen not found"
        path = self.workdir / name
        subprocess.run(
            [keygen, "-t", "ed25519", "-f", str(path), "-N", ""],
            cwd=self.workdir,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        return path


def initialize(cli: Cli, api_port: int) -> None:
    """`tests/fixture.sh`: initialize the tenant and log the admin in."""
    cli.keygen("account")
    cli.run(
        "pfa",
        "-c",
        "config.json",
        "initialize",
        f"http://127.0.0.1:{api_port}/pf/t/root/directory",
        "--key",
        "account",
    )
    cli.keygen("session")
    cli.run("pfa", "-c", "config.json", "login", "--session-key", "session")


def accept_and_login(cli: Cli, config: str, invitation: str, name: str) -> None:
    """Provision an identity's keys: accept the invitation, then log in.

    The `.t` files repeat this verbatim for every host and user.
    """
    cli.keygen(f"{name}-account")
    cli.run("pf", "-c", config, "accept", f"--invitation={invitation}", "--key", f"{name}-account")
    cli.keygen(f"{name}-session")
    cli.run("pf", "-c", config, "login", "--session-key", f"{name}-session")
