"""What every platform provider receives and offers."""

from __future__ import annotations

import dataclasses
import typing

from . import ops


@dataclasses.dataclass(frozen=True)
class Settings:
    invitation: str
    directory_url: str
    host_keys_dir: str
    ca_pub_path: str
    sshd_config_drop_in: str
    auth_user: str
    # The pf that sshd and the services run. None lets the provider choose.
    pf_binary: str | None = None
    # Windows only: sshd keeps its configuration in one file that must be edited, and runs as a service.
    sshd_config: str | None = None
    sshd_service: str = "sshd"


@dataclasses.dataclass(frozen=True)
class Defaults:
    """The command line defaults of a platform."""

    host_keys_dir: str
    ca_pub_path: str
    sshd_config_drop_in: str
    auth_user: str


class Provider(typing.Protocol):
    def init(self, o: ops.Ops, settings: Settings) -> None:
        """Set up the local SSH daemon to trust pf."""

    def uninit(self, o: ops.Ops, settings: Settings) -> None:
        """Undo `init`."""

    def reload_sshd(self, o: ops.Ops) -> None:
        """Make the running SSH daemon read its new configuration, if it needs that."""
