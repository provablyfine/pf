from __future__ import annotations

import dataclasses
import json
import os

from . import exceptions


@dataclasses.dataclass
class Config:
    directory_url: str
    account_key: str | None = None
    session_key: str | None = None
    directory: dict[str, str] | None = None
    known_hosts: str | None = None
    auth_name: str | None = None

    @staticmethod
    def load(filename: str) -> Config:
        try:
            with open(filename) as f:
                data = json.load(f)
                return Config(**data)
        except Exception:
            raise exceptions.UI(f"Unable to load {filename}")

    def save(self, filename: str):
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        with open(filename, "w+") as f:
            json.dump(dataclasses.asdict(self), f)
