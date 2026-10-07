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
import re
import shlex
import shutil
import stat
import subprocess
import sys
import typing

import provablyfine_client as pfc

from .... import client


@dataclasses.dataclass(frozen=True)
class MakeDir:
    path: str
    mode: int
    # User that owns the directory. None keeps the current owner.
    owner: str | None = None


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


@dataclasses.dataclass(frozen=True)
class Note:
    text: str


Action = MakeDir | WriteFile | Remove | Run | Note


@dataclasses.dataclass(frozen=True)
class QueryResult:
    returncode: int
    stdout: str
    stderr: str = ""


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
    return QueryResult(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)


def _quote(argument: str) -> str:
    """Quote an argument the way the platform's own shell would, so a person can read it."""
    if sys.platform == "win32":
        return subprocess.list2cmdline([argument])
    return shlex.quote(argument)


def _decode(content: bytes) -> str:
    """Text for a person to read. Windows tools such as the task scheduler want UTF-16."""
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        return content.decode("utf-16", errors="replace")
    return content.decode("utf-8", errors="replace")


def describe(action: Action) -> str:
    match action:
        case MakeDir(path=path, mode=mode, owner=owner):
            owned = f" (owner {owner})" if owner else ""
            return f"mkdir -m {mode:o} {_quote(path)}{owned}"
        case WriteFile(path=path, content=content, mode=mode, secret=secret):
            mode_text = "keep mode" if mode is None else f"mode {mode:o}"
            header = f"write {_quote(path)} ({mode_text}, {len(content)} bytes)"
            if secret:
                return header + "\n  (content not shown)"
            text = _decode(content).rstrip("\r\n")
            return header + "\n" + "\n".join("  | " + line for line in text.split("\n"))
        case Remove(path=path, recursive=recursive):
            return f"rm {'-r ' if recursive else ''}{_quote(path)}"
        case Note(text=text):
            return f"note: {text}"
        case Run(argv=argv, check=check, stdin=stdin):
            text = "run " + " ".join(_quote(a) for a in argv)
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
            # newline="" keeps CRLF as it is: a file that is read and written back must not change its line endings.
            with open(path, encoding="utf-8", newline="") as f:
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

    def _realpath(self, path: str) -> str:
        return os.path.realpath(path)

    def _stat(self, path: str) -> os.stat_result:
        return os.stat(path)

    def path_problem(self, path: str, trusted_uid: int = 0) -> str | None:
        """Why sshd would refuse to run `path` as a command, or None if it would accept it.

        sshd wants the file and every directory above it to belong to a
        trusted user and to be closed to writes by group and others.
        """
        current = self._realpath(path)
        while True:
            try:
                info = self._stat(current)
            except OSError as e:
                return f"cannot inspect {current}: {e.strerror}"
            if info.st_uid != trusted_uid:
                return f"{current} is owned by uid {info.st_uid}, not {trusted_uid}"
            if info.st_mode & 0o022:
                return f"{current} can be written by its group or by others (mode {stat.S_IMODE(info.st_mode):o})"
            parent = os.path.dirname(current)
            if parent == current:
                return None
            current = parent

    @abc.abstractmethod
    def note(self, text: str) -> None: ...

    @abc.abstractmethod
    def make_dir(self, path: str, mode: int, owner: str | None = None) -> None: ...

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

    def note(self, text: str) -> None:
        sys.stderr.write(f"note: {text}\n")

    def make_dir(self, path: str, mode: int, owner: str | None = None) -> None:
        os.makedirs(path, exist_ok=True)
        os.chmod(path, mode)
        if owner is not None:
            shutil.chown(path, user=owner)

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
        # pf refuses to log in when it sees these, and children would inherit
        # them from the sudo that started host-init.
        environment = {name: value for name, value in os.environ.items() if not name.startswith("SUDO_")}
        try:
            result = subprocess.run(  # noqa: S603
                list(argv),
                check=False,
                input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
                env=environment,
            )
        except FileNotFoundError as e:
            if check:
                raise pfc.exceptions.UI(f"command not found: {argv[0]}") from e
            return
        if check and result.returncode != 0:
            raise pfc.exceptions.UI(
                f"command failed with exit code {result.returncode}: {' '.join(_quote(a) for a in argv)}"
            )


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
        trusted_uid: int = 0,
    ) -> None:
        self.actions: list[Action] = []
        self._root = root
        self._query = query or run_query
        self._trusted_uid = trusted_uid

    def _real(self, path: str) -> str:
        if self._root is None:
            return path
        # A Windows path such as C:\ProgramData\ssh becomes the directory drive_c/ProgramData/ssh
        # under the root. A colon cannot be part of a file name in a CI artifact.
        posix = path.replace("\\", "/")
        return str(self._root / re.sub(r"^([A-Za-z]):/", lambda m: f"drive_{m[1].lower()}/", posix).lstrip("/"))

    def _logical(self, path: str) -> str:
        if self._root is None:
            return path
        relative = os.path.relpath(path, self._root).replace(os.sep, "/")
        drive = re.match(r"drive_([a-z])/", relative)
        return f"{drive[1].upper()}:/{relative[len(drive[0]) :]}" if drive else "/" + relative

    def _realpath(self, path: str) -> str:
        # A test root has no symbolic links to resolve.
        return super()._realpath(path) if self._root is None else path

    def _stat(self, path: str) -> os.stat_result:
        if self._root is not None and path == "/":
            return os.stat(self._root)
        return os.stat(self._real(path))

    def path_problem(self, path: str, trusted_uid: int = 0) -> str | None:
        return super().path_problem(path, self._trusted_uid if self._root is not None else trusted_uid)

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

    def note(self, text: str) -> None:
        self.actions.append(Note(text))

    def make_dir(self, path: str, mode: int, owner: str | None = None) -> None:
        self.actions.append(MakeDir(path, mode, owner))

    def write_file(self, path: str, content: bytes | str, mode: int | None, *, secret: bool = False) -> None:
        self.actions.append(WriteFile(path, _as_bytes(content), mode, secret))

    def remove(self, path: str, *, recursive: bool = False) -> None:
        self.actions.append(Remove(path, recursive))

    def run(self, argv: typing.Sequence[str], *, check: bool = True, stdin: bytes | None = None) -> None:
        self.actions.append(Run(tuple(argv), check, stdin))

    def describe(self) -> str:
        return "\n".join(describe(action) for action in self.actions) + "\n"
