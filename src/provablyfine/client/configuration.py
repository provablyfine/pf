from __future__ import annotations

import collections.abc
import contextlib
import dataclasses
import json
import os
import tempfile
import time
import typing

import provablyfine_client as pfc

from . import _filelock

DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "provablyfine", "config.json")

_LOCK_TIMEOUT_SECONDS = 5.0


def write_file_atomic(
    filepath: str,
    content: bytes | str,
    mode: str = "wb",
    *,
    permissions: int = 0o644,
) -> None:
    """Write `content` to `filepath`, atomically replacing any existing file.

    os.replace, not os.rename: identical on POSIX, but os.rename refuses an
    existing destination on Windows (WinError 183)
    """
    dirname = os.path.dirname(filepath) or "."
    os.makedirs(dirname, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=dirname)
    try:
        with os.fdopen(fd, mode) as f:
            f.write(content)
        os.chmod(tmp_path, permissions)
        os.replace(tmp_path, filepath)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


@contextlib.contextmanager
def _registry_lock(filename: str) -> collections.abc.Generator[None]:
    """A cross-process mutex over the registry file `filename`, held on a
    sidecar file with an OS-level lock.

    The OS drops the lock when its owner dies, so a crashed process never
    blocks the others. The sidecar file itself is never deleted.

    Only writers take it. Readers don't need it, because the registry is
    always replaced atomically.

    Raises `OSError` if the sidecar cannot be created, for example on a
    read-only directory.
    """
    lock_path = filename + ".lock"
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while not _filelock.try_lock(fd):
            if time.monotonic() >= deadline:
                raise pfc.exceptions.UI(f"Timed out waiting for the lock {lock_path}") from None
            time.sleep(0.05)
        try:
            yield
        finally:
            _filelock.unlock(fd)
    finally:
        os.close(fd)


def _config_from_legacy_dict(data: dict[str, typing.Any]) -> Config:
    """Build a `Config` from the pre-registry, single-tenant JSON shape,
    including its own older back-compat massaging (a single "account_key"/
    "session_key" field, split into today's *_fingerprint/*_file pair
    depending on whether the value is an on-disk path).
    """
    data = dict(data)
    for legacy_key, fingerprint_key, file_key in (
        ("account_key", "account_key_fingerprint", "account_key_file"),
        ("session_key", "session_key_fingerprint", "session_key_file"),
    ):
        if legacy_key in data:
            val = data.pop(legacy_key)
            if val is not None:
                assert isinstance(val, str)
                if os.path.exists(val):
                    data.setdefault(file_key, val)
                else:
                    data.setdefault(fingerprint_key, val)
    return Config(**data)


def _auto_name(config: Config, existing: collections.abc.Iterable[str]) -> str:
    """Derive a context name from `config`'s tenant, disambiguating against
    `existing` names with a numeric suffix."""
    existing_set = set(existing)
    base = config.tenant_name or "default"
    if base not in existing_set:
        return base
    i = 2
    while f"{base}-{i}" in existing_set:
        i += 1
    return f"{base}-{i}"


@dataclasses.dataclass
class Config:
    directory_url: str
    account_key_fingerprint: str | None = None
    account_key_file: str | None = None
    session_key_fingerprint: str | None = None
    session_key_file: str | None = None
    session_key_pem: str | None = None
    directory: dict[str, str] | None = None
    known_hosts: str | None = None
    auth_name: str | None = None
    role_id: int | None = None  # headless only: set from invitation URL, consumed by ensure_session
    # The tenant name is read from the directory when the context is created.
    # It is only a label: the directory URL holds a UUID, not the name.
    tenant_name: str = ""

    def __post_init__(self) -> None:
        self.ephemeral: bool = False
        self.session_expires_at: int | None = None
        # The name this config is stored under in its Registry, or None for a
        # freshly-constructed Config with no registry entry yet. Never
        # persisted (not a dataclass field) -- see save() below, which
        # branches on it to decide "new context" vs. "update in place".
        self.context_name: str | None = None

    @staticmethod
    def load(filename: str) -> Config:
        registry = Registry.load(filename)
        cfg = registry.current_config()
        cfg.context_name = registry.current
        return cfg

    def save(self, filename: str) -> None:
        if self.ephemeral:
            raise RuntimeError(
                "Cannot save an ephemeral config: session was obtained non-interactively "
                "and must not be persisted to disk."
            )
        if filename == os.devnull:
            return
        with Registry.transaction(filename) as registry:
            # Contexts are matched by directory_url, not by name: another
            # shell (or the TUI's switcher) may have renamed this context
            # since it was loaded, and saving under the stale name would
            # create a duplicate.
            existing = registry.name_for_url(self.directory_url, prefer=self.context_name)
            if self.context_name is None:
                if existing is not None:
                    raise _duplicate_url_error(existing, self.directory_url)
                name = _auto_name(self, registry.contexts.keys())
                registry.previous = registry.current
                registry.current = name
                self.context_name = name
            else:
                name = existing or self.context_name
                self.context_name = name
            registry.contexts[name] = self


def _duplicate_url_error(name: str, directory_url: str) -> pfc.exceptions.UI:
    return pfc.exceptions.UI(
        f"Context {name!r} already targets {directory_url}. "
        f"Use it (ctx use {name}) or delete it first (ctx delete {name})."
    )


@dataclasses.dataclass
class Registry:
    """The on-disk registry of named tenant contexts living at a `-c/--config`
    path: `{"current": ..., "previous": ..., "contexts": {name: Config, ...}}`.

    `previous` and `contexts` are never scanned for `ephemeral` configs when
    saving: an ephemeral config is always the *current* one (a headless
    session), and `Config.save()` already refuses to persist it before this
    type is ever touched. The other contexts on disk remain saveable
    independent of it.
    """

    contexts: dict[str, Config]
    current: str | None = None
    previous: str | None = None

    @staticmethod
    def load(filename: str) -> Registry:
        """Read the registry. This never writes, except to migrate a legacy
        file, and a failure to do that is not an error: the migrated form is
        simply used from memory until the next writer saves it."""
        registry, legacy = Registry._read(filename)
        if not legacy:
            return registry
        try:
            with _registry_lock(filename):
                # Someone else may have migrated it while we waited.
                registry, legacy = Registry._read(filename)
                if legacy:
                    registry.save_locked(filename)
        except OSError:
            pass
        return registry

    @staticmethod
    def _read(filename: str) -> tuple[Registry, bool]:
        """Returns the registry, and whether the file is in the legacy,
        pre-registry, single-tenant shape (in which case the registry is its
        migrated form and the file still has to be rewritten)."""
        if not os.path.exists(filename):
            return Registry(contexts={}), False
        try:
            with open(filename) as f:
                data = json.load(f)
        except Exception:
            raise pfc.exceptions.UI(f"Unable to load {filename}") from None

        try:
            if "contexts" in data:
                contexts = {name: Config(**ctx) for name, ctx in data["contexts"].items()}
                return Registry(contexts=contexts, current=data.get("current"), previous=data.get("previous")), False
            config = _config_from_legacy_dict(data)
            name = config.tenant_name or "default"
            return Registry(contexts={name: config}, current=name, previous=None), True
        except pfc.exceptions.UI:
            raise
        except Exception:
            raise pfc.exceptions.UI(f"Unable to load {filename}") from None

    def current_config(self) -> Config:
        if self.current is None or self.current not in self.contexts:
            raise pfc.exceptions.UI("No current context. Run 'accept'/'initialize', or 'ctx <name>', first.")
        return self.contexts[self.current]

    def save(self, filename: str) -> None:
        try:
            with _registry_lock(filename):
                self.save_locked(filename)
        except OSError as e:
            raise pfc.exceptions.UI(f"Unable to write {filename}: {e}") from e

    @staticmethod
    @contextlib.contextmanager
    def transaction(filename: str) -> collections.abc.Generator[Registry]:
        """Load the registry, yield it for modification, and save it on a
        clean exit. The lock is held throughout, so concurrent changes made
        by other processes are never overwritten with a stale snapshot.

        If the body raises, nothing is written.
        """
        try:
            with _registry_lock(filename):
                registry, _ = Registry._read(filename)
                yield registry
                registry.save_locked(filename)
        except OSError as e:
            raise pfc.exceptions.UI(f"Unable to write {filename}: {e}") from e

    @staticmethod
    def ensure_url_available(filename: str, directory_url: str) -> None:
        """Raise if a context already targets `directory_url`.

        Call this before consuming an invitation: `Config.save` refuses
        duplicates too, but by then the invitation is already spent.
        """
        registry = Registry.load(filename)
        name = registry.name_for_url(directory_url)
        if name is not None:
            raise _duplicate_url_error(name, directory_url)

    def name_for_url(self, directory_url: str, prefer: str | None = None) -> str | None:
        """The name of the context targeting `directory_url`, if any.

        A directory URL is meant to be unique. If an older registry holds
        duplicates anyway, `prefer` picks between them.
        """
        matches = [name for name, cfg in self.contexts.items() if cfg.directory_url == directory_url]
        if prefer in matches:
            return prefer
        return matches[0] if matches else None

    def _check_exists(self, name: str) -> None:
        if name not in self.contexts:
            raise pfc.exceptions.UI(f"No such context: {name!r}. Available: {', '.join(sorted(self.contexts))}")

    def use(self, name: str) -> bool:
        """Make `name` the current context. Returns False if it already was."""
        self._check_exists(name)
        if name == self.current:
            return False
        self.previous = self.current
        self.current = name
        return True

    def use_previous(self) -> None:
        if self.previous is None or self.previous not in self.contexts:
            raise pfc.exceptions.UI("No previous context to switch to")
        self.current, self.previous = self.previous, self.current

    def rename(self, old: str, new: str) -> None:
        self._check_exists(old)
        if new == old:
            return
        if new in self.contexts:
            raise pfc.exceptions.UI(f"Context {new!r} already exists")
        self.contexts[new] = self.contexts.pop(old)
        if self.current == old:
            self.current = new
        if self.previous == old:
            self.previous = new

    def delete(self, name: str) -> None:
        self._check_exists(name)
        if name == self.current:
            raise pfc.exceptions.UI(f"Cannot delete the current context {name!r}. Switch away first.")
        del self.contexts[name]
        if self.previous == name:
            self.previous = None

    @staticmethod
    def set_session_fingerprint(filename: str, directory_url: str, fingerprint: str | None) -> None:
        """Point the context targeting `directory_url` at the oracle-held
        session key `fingerprint`, leaving everything else untouched."""
        with Registry.transaction(filename) as registry:
            name = registry.name_for_url(directory_url)
            if name is None:
                return
            saved = registry.contexts[name]
            saved.session_key_fingerprint = fingerprint
            saved.session_key_file = None
            saved.session_key_pem = None

    def save_locked(self, filename: str) -> None:
        """Unlocked variant of `save`, for callers that already hold the lock."""
        if filename == os.devnull:
            return
        data = {
            "current": self.current,
            "previous": self.previous,
            "contexts": {name: dataclasses.asdict(cfg) for name, cfg in self.contexts.items()},
        }
        write_file_atomic(filename, json.dumps(data), mode="w", permissions=0o600)
