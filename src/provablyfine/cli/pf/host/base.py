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


class Provider(typing.Protocol):
    def init(self, o: ops.Ops, settings: Settings) -> None:
        """Set up the local SSH daemon to trust pf."""

    def uninit(self, o: ops.Ops, settings: Settings) -> None:
        """Undo `init`."""

    def reload_sshd(self, o: ops.Ops) -> None:
        """Make the running SSH daemon read its new configuration, if it needs that."""
