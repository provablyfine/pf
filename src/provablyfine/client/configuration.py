from __future__ import annotations

import dataclasses
import json
import os

import provablyfine_client as pfc


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
        dirname = os.path.dirname(os.path.abspath(filename))
        os.makedirs(dirname, exist_ok=True)
        tmp = filename + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(dataclasses.asdict(self), f)
        os.rename(tmp, filename)
