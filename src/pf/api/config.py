from __future__ import annotations

import dataclasses
import json
import os.path

import yaml


@dataclasses.dataclass
class DefaultBastion:
    register_url: str | None = None
    connect_url: str | None = None
    ssh_proxy_jump: str | None = None


@dataclasses.dataclass
class Config:
    debug: bool = False
    debug_sql: bool = False
    log_level: str = "ERROR"
    base_url: str = "http://127.0.0.1:8000"
    tenant_registry_url: str = "sqlite:///tenants.db"
    tenants_dir: str = "tenants"
    kek_filename: str = "kek.key"
    session_duration_s: int = 3600
    bastion_private_key_filename: str = "bastion-private.key"

    host_key_staging_period: int = 12 * 3600
    host_key_rotation_period: int = 24 * 3600
    host_key_type: str = "ed25519"
    host_certificate_lifetime: int = 24 * 3600

    user_key_staging_period: int = 12 * 3600
    user_key_rotation_period: int = 24 * 3600
    user_key_type: str = "ed25519"
    user_certificate_lifetime: int = 60
    user_extra_trusted_keys_filename: str = "user-trusted-key.pub"

    oidc_key_staging_period: int = 7 * 86400
    oidc_key_rotation_period: int = 30 * 86400

    default_bastion: DefaultBastion | None = None

    def __post_init__(self):
        if isinstance(self.default_bastion, dict):
            self.default_bastion = DefaultBastion(**self.default_bastion)

    @staticmethod
    def load(filename: str | None = None) -> Config:
        if filename is None:
            data = {}
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
        config = Config(**data)
        return config
