from __future__ import annotations

import dataclasses
import json
import os
import re
import tempfile

import provablyfine_client as pfc

_TENANT_URL_RE = re.compile(r"/pf/t/([^/]+)/")


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

    def __post_init__(self) -> None:
        self.ephemeral: bool = False
        self.session_expires_at: int | None = None

    @property
    def tenant_name(self) -> str:
        """Tenant slug embedded in `directory_url` (`.../pf/t/<slug>/directory`), or
        `""` if the URL doesn't follow that shape."""
        match = _TENANT_URL_RE.search(self.directory_url)
        return match.group(1) if match else ""

    @staticmethod
    def load(filename: str) -> Config:
        try:
            with open(filename) as f:
                data = json.load(f)
            if "account_key" in data:
                val = data.pop("account_key")
                if val is not None:
                    if os.path.exists(val):
                        data.setdefault("account_key_file", val)
                    else:
                        data.setdefault("account_key_fingerprint", val)
            if "session_key" in data:
                val = data.pop("session_key")
                if val is not None:
                    if os.path.exists(val):
                        data.setdefault("session_key_file", val)
                    else:
                        data.setdefault("session_key_fingerprint", val)
            return Config(**data)
        except Exception:
            raise pfc.exceptions.UI(f"Unable to load {filename}")

    def save(self, filename: str) -> None:
        if self.ephemeral:
            raise RuntimeError(
                "Cannot save an ephemeral config: session was obtained non-interactively "
                "and must not be persisted to disk."
            )
        if filename == os.devnull:
            return
        write_file_atomic(filename, json.dumps(dataclasses.asdict(self)), mode="w", permissions=0o600)
