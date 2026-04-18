import typing

import textual
import textual.app
import textual.containers
import textual.reactive
import textual.screen
import textual.widgets

from ... import client
from ...client import schemas
from .. import header
from .base import _GrantEditWidget
from .boundary import BoundaryGrantEditWidget
from .identity import IdentityGrantEditWidget
from .role import RoleGrantEditWidget
from .ssh_command import SshCommandGrantEditWidget
from .ssh_port_forward import SshPortForwardingGrantEditWidget
from .ssh_shell import SshShellGrantEditWidget
from .tag import TagGrantEditWidget
from .tenant import TenantGrantEditWidget


class GrantEditScreen(textual.screen.Screen[schemas.Grant | None]):
    DEFAULT_CSS = """
    .sections {
        padding: 0 1;
    }
    .section {
        padding: 1 0 0 0;
    }
    .label {
        padding: 0 0;
    }
    """
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "confirm", "Confirm"),
        ("escape", "cancel", "Cancel"),
        ("up", "app.focus_previous", ""),
        ("down", "app.focus_next", ""),
    ]
    grant_type: textual.reactive.Reactive[str] = textual.reactive.Reactive("")

    def __init__(self, auth: client.aio.Client, grant: schemas.Grant):
        super().__init__(id="grant-edit")
        self._auth = auth
        self._grant = grant
        self.grant_type = grant.type

    async def watch_grant_type(self, value: str) -> None:
        self.sub_title = f"Edit {value} grant"
        fields = self.query_one("#dynamic-grant-fields")
        await fields.query("*").remove()
        match value:
            case "role":
                widget: _GrantEditWidget = RoleGrantEditWidget(self._auth, self._grant)
            case "identity":
                widget = IdentityGrantEditWidget(self._auth, self._grant)
            case "tag":
                widget = TagGrantEditWidget(self._auth, self._grant)
            case "boundary":
                widget = BoundaryGrantEditWidget(self._auth, self._grant)
            case "tenant":
                widget = TenantGrantEditWidget(self._auth, self._grant)
            case "ssh-shell":
                widget = SshShellGrantEditWidget(self._auth, self._grant)
            case "ssh-port-forwarding":
                widget = SshPortForwardingGrantEditWidget(self._auth, self._grant)
            case "ssh-command":
                widget = SshCommandGrantEditWidget(self._auth, self._grant)
            case _:
                return
        await fields.mount(widget)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_confirm(self) -> None:
        widgets = list(self.query_one("#dynamic-grant-fields").query(_GrantEditWidget))
        if not widgets:
            return
        self.dismiss(widgets[0].get_grant_data())

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.VerticalGroup(classes="sections"):
            yield textual.containers.Container(id="dynamic-grant-fields")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)
