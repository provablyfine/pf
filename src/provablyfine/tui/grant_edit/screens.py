import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.reactive
import textual.screen
import textual.widgets

from .. import header
from . import base, boundary, identity, role, ssh_command, ssh_port_forward, ssh_shell, tag, tenant


class GrantEditScreen(textual.screen.Screen[pfc.schemas.Grant | None]):
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

    def __init__(self, auth: pfc.AsyncSessionClient, grant: pfc.schemas.Grant):
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
                widget = role.RoleGrantEditWidget(self._auth, typing.cast(pfc.schemas.RoleGrant, self._grant))
            case "identity":
                widget = identity.IdentityGrantEditWidget(
                    self._auth, typing.cast(pfc.schemas.IdentityGrant, self._grant)
                )
            case "tag":
                widget = tag.TagGrantEditWidget(self._auth, typing.cast(pfc.schemas.TagGrant, self._grant))
            case "boundary":
                widget = boundary.BoundaryGrantEditWidget(
                    self._auth, typing.cast(pfc.schemas.BoundaryGrant, self._grant)
                )
            case "tenant":
                widget = tenant.TenantGrantEditWidget(self._auth, typing.cast(pfc.schemas.TenantGrant, self._grant))
            case "ssh-shell":
                widget = ssh_shell.SshShellGrantEditWidget(
                    self._auth, typing.cast(pfc.schemas.SSHShellGrant, self._grant)
                )
            case "ssh-port-forwarding":
                widget = ssh_port_forward.SshPortForwardingGrantEditWidget(
                    self._auth, typing.cast(pfc.schemas.SSHPortForwardingGrant, self._grant)
                )
            case "ssh-command":
                widget = ssh_command.SshCommandGrantEditWidget(
                    self._auth, typing.cast(pfc.schemas.SSHCommandGrant, self._grant)
                )
            case _:
                return
        await fields.mount(widget)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_confirm(self) -> None:
        widgets = list(self.query_one("#dynamic-grant-fields").query(base.GrantEditWidget))
        if not widgets:
            return
        self.dismiss(widgets[0].get_grant_data())

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.VerticalGroup(classes="sections"):
            yield textual.containers.Container(id="dynamic-grant-fields")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)
