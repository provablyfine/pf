"""The operations host-init applies to the machine.

Providers describe what to do through `Ops`. They never touch the system
directly.

Read-only methods always run, even in a dry run. Changing methods run in
`SystemOps` and are only recorded in `DryRunOps`.

Commands are argument lists. No shell ever parses them.
"""

from __future__ import annotations

import abc
import dataclasses
import glob
import os
import pathlib
import shlex
import shutil
import subprocess
import typing

import provablyfine_client as pfc

from .... import client


@dataclasses.dataclass(frozen=True)
class MakeDir:
    path: str
    mode: int


@dataclasses.dataclass(frozen=True)
class WriteFile:
    path: str
    content: bytes
    # None keeps the mode of an existing file and uses 0o644 for a new one.
    mode: int | None
    # The content is not shown in a dry run.
    secret: bool = False


@dataclasses.dataclass(frozen=True)
class Remove:
    path: str
    recursive: bool = False


@dataclasses.dataclass(frozen=True)
class Run:
    argv: tuple[str, ...]
    check: bool
    stdin: bytes | None


Action = MakeDir | WriteFile | Remove | Run


@dataclasses.dataclass(frozen=True)
class QueryResult:
    returncode: int
    stdout: str


def run_query(argv: typing.Sequence[str]) -> QueryResult:
    try:
        result = subprocess.run(  # noqa: S603
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return QueryResult(returncode=127, stdout="")
    return QueryResult(returncode=result.returncode, stdout=result.stdout)


def describe(action: Action) -> str:
    match action:
        case MakeDir(path=path, mode=mode):
            return f"mkdir -m {mode:o} {shlex.quote(path)}"
        case WriteFile(path=path, content=content, mode=mode, secret=secret):
            mode_text = "keep mode" if mode is None else f"mode {mode:o}"
            header = f"write {shlex.quote(path)} ({mode_text}, {len(content)} bytes)"
            if secret:
                return header + "\n  (content not shown)"
            text = content.decode("utf-8", errors="replace").rstrip("\n")
            return header + "\n" + "\n".join("  | " + line for line in text.split("\n"))
        case Remove(path=path, recursive=recursive):
            return f"rm {'-r ' if recursive else ''}{shlex.quote(path)}"
        case Run(argv=argv, check=check, stdin=stdin):
            text = "run " + shlex.join(argv)
            if stdin is not None:
                text += f"  (stdin: {len(stdin)} bytes, not shown)"
            if not check:
                text += "  (failure ignored)"
            return text


class Ops(abc.ABC):
    """Read-only helpers, plus the changing operations a provider needs."""

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def is_executable(self, path: str) -> bool:
        return os.path.isfile(path) and os.access(path, os.X_OK)

    def read_text(self, path: str) -> str | None:
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except (FileNotFoundError, IsADirectoryError):
            return None

    def list_dir(self, path: str) -> list[str]:
        try:
            return sorted(os.path.join(path, name) for name in os.listdir(path))
        except FileNotFoundError:
            return []

    def glob(self, pattern: str) -> list[str]:
        return sorted(glob.glob(pattern))

    def query(self, argv: typing.Sequence[str]) -> QueryResult:
        return run_query(argv)

    @abc.abstractmethod
    def make_dir(self, path: str, mode: int) -> None: ...

    @abc.abstractmethod
    def write_file(self, path: str, content: bytes | str, mode: int | None, *, secret: bool = False) -> None: ...

    @abc.abstractmethod
    def remove(self, path: str, *, recursive: bool = False) -> None: ...

    @abc.abstractmethod
    def run(self, argv: typing.Sequence[str], *, check: bool = True, stdin: bytes | None = None) -> None: ...


def _as_bytes(content: bytes | str) -> bytes:
    return content.encode("utf-8") if isinstance(content, str) else content


class SystemOps(Ops):
    """Apply the operations to the machine."""

    def make_dir(self, path: str, mode: int) -> None:
        os.makedirs(path, exist_ok=True)
        os.chmod(path, mode)

    def write_file(self, path: str, content: bytes | str, mode: int | None, *, secret: bool = False) -> None:
        if mode is None:
            try:
                mode = os.stat(path).st_mode & 0o7777
            except FileNotFoundError:
                mode = 0o644
        client.configuration.write_file_atomic(path, _as_bytes(content), mode="wb", permissions=mode)

    def remove(self, path: str, *, recursive: bool = False) -> None:
        if recursive:
            shutil.rmtree(path, ignore_errors=True)
            return
        pathlib.Path(path).unlink(missing_ok=True)

    def run(self, argv: typing.Sequence[str], *, check: bool = True, stdin: bytes | None = None) -> None:
        try:
            result = subprocess.run(  # noqa: S603
                list(argv),
                check=False,
                input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
            )
        except FileNotFoundError as e:
            if check:
                raise pfc.exceptions.UI(f"command not found: {argv[0]}") from e
            return
        if check and result.returncode != 0:
            raise pfc.exceptions.UI(f"command failed with exit code {result.returncode}: {shlex.join(argv)}")


class DryRunOps(Ops):
    """Record the changing operations without applying them.

    `root` makes the read-only helpers look under another directory, so tests
    can use a temporary tree. `query` replaces the command runner used by
    `Ops.query`.
    """

    def __init__(
        self,
        root: pathlib.Path | None = None,
        query: typing.Callable[[typing.Sequence[str]], QueryResult] | None = None,
    ) -> None:
        self.actions: list[Action] = []
        self._root = root
        self._query = query or run_query

    def _real(self, path: str) -> str:
        if self._root is None:
            return path
        return str(self._root / path.lstrip("/"))

    def _logical(self, path: str) -> str:
        if self._root is None:
            return path
        return "/" + os.path.relpath(path, self._root)

    def exists(self, path: str) -> bool:
        return super().exists(self._real(path))

    def is_executable(self, path: str) -> bool:
        return super().is_executable(self._real(path))

    def read_text(self, path: str) -> str | None:
        return super().read_text(self._real(path))

    def list_dir(self, path: str) -> list[str]:
        return [self._logical(p) for p in super().list_dir(self._real(path))]

    def glob(self, pattern: str) -> list[str]:
        return [self._logical(p) for p in super().glob(self._real(pattern))]

    def query(self, argv: typing.Sequence[str]) -> QueryResult:
        return self._query(argv)

    def make_dir(self, path: str, mode: int) -> None:
        self.actions.append(MakeDir(path, mode))

    def write_file(self, path: str, content: bytes | str, mode: int | None, *, secret: bool = False) -> None:
        self.actions.append(WriteFile(path, _as_bytes(content), mode, secret))

    def remove(self, path: str, *, recursive: bool = False) -> None:
        self.actions.append(Remove(path, recursive))

    def run(self, argv: typing.Sequence[str], *, check: bool = True, stdin: bytes | None = None) -> None:
        self.actions.append(Run(tuple(argv), check, stdin))

    def describe(self) -> str:
        return "\n".join(describe(action) for action in self.actions) + "\n"
