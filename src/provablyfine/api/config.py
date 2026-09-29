from __future__ import annotations

import json
import os
import os.path
import typing

import cryptography.exceptions
import pydantic
import yaml

from .. import base64url, jwk
from . import unix_account


class DefaultBastion(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")

    url: str | None = None
    ssh_proxy_jump: str | None = None


class SendmailEmailConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")

    type: typing.Literal["sendmail"] = "sendmail"
    from_address: str
    sendmail_path: str = "/usr/sbin/sendmail"


class ResendEmailConfig(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")

    type: typing.Literal["resend"] = "resend"
    from_address: str
    api_key_filename: str


EmailConfig = typing.Annotated[
    SendmailEmailConfig | ResendEmailConfig,
    pydantic.Field(discriminator="type"),
]


class Config(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")

    debug: bool = False
    debug_sql: bool = False
    docs_enabled: bool = False
    log_level: int = 0
    log_filename: str | None = None
    base_url: str = "http://127.0.0.1:8000"
    tenant_registry_url: str = "sqlite:///tenants.db"
    kek_filename: str = "kek.key"
    session_duration_s: int = 3600
    privileged_unix_usernames: list[str] = pydantic.Field(
        default_factory=lambda: list(unix_account.DEFAULT_PRIVILEGED_USERNAMES)
    )

    host_key_staging_period: int = 12 * 3600
    host_key_rotation_period: int = 24 * 3600
    host_key_type: str = "ed25519"
    host_certificate_lifetime: int = 24 * 3600

    user_key_staging_period: int = 12 * 3600
    user_key_rotation_period: int = 24 * 3600
    user_key_type: str = "ed25519"
    user_certificate_lifetime: int = 60
    user_extra_trusted_keys_filename: str | None = None

    oidc_key_grace_period: int = 7 * 86400
    oidc_key_rotation_period: int = 30 * 86400
    oidc_key_staging_period: int = 7 * 86400

    default_bastion: DefaultBastion | None = None
    email: EmailConfig | None = None

    @staticmethod
    def load(filename: str | None = None) -> Config:
        if filename is None:
            data: dict[str, object] = {}
        else:
            if not os.path.exists(filename):
                data = {}
            elif filename.endswith(".json"):
                with open(filename) as f:
                    data = json.load(f)
            elif filename.endswith(".yaml") or filename.endswith(".yml"):
                with open(filename) as f:
                    data = yaml.safe_load(f)
            else:
                assert False
        return Config.model_validate(data)

    def load_kek(self) -> str:
        """Read the key encryption key file and return it as a Fernet key string."""
        filename = self.kek_filename.format(PF_SECRET_DIRECTORY=os.getenv("PF_SECRET_DIRECTORY", ""))
        with open(filename, "rb") as f:
            raw = f.read()
        if len(raw) != 32:
            raise ValueError(f"KEK file {filename} must contain exactly 32 random bytes, found {len(raw)}")
        return base64url.encode(raw, pad=True)

    def load_user_extra_trusted_keys(self) -> list[bytes]:
        """Read the extra user CA keys named by `user_extra_trusted_keys_filename`.

        Returns no keys when no file is configured.
        A configured file must contain at least one valid key.
        Blank lines and `#` comments are skipped.
        Each key is returned in its normalized OpenSSH form, one per entry.
        """
        filename = self.user_extra_trusted_keys_filename
        if filename is None:
            return []
        with open(filename, "rb") as f:
            lines = f.read().splitlines()
        keys: list[bytes] = []
        for number, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            try:
                keys.append(jwk.Public.from_openssh(line).to_openssh())
            except (ValueError, cryptography.exceptions.UnsupportedAlgorithm) as e:
                raise ValueError(f"{filename}:{number}: not a valid OpenSSH public key: {e}") from e
        if not keys:
            raise ValueError(f"{filename} does not contain any public key")
        return keys
