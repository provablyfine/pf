import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets

from .. import checkbox_input
from . import base


class SshCommandGrantEditWidget(base.TripletFilterGrantEditWidget[pfc.schemas.SSHCommandGrant]):
    DEFAULT_CSS = """
    SshCommandGrantEditWidget {
        height: auto;
    }
    """

    def compose(self) -> textual.app.ComposeResult:
        p = self._grant.permission
        username_field = base.Field(active=True, value=" ".join(p.username_list or []))
        command_field = base.Field(active=True, value=" ".join(p.command_list or []))
        yield from self._compose_filter()
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield checkbox_input.CheckboxInput(
                "Usernames",
                active=True,
                value=username_field.value,
                placeholder="Type a username",
                id="perm-username-list",
            )
            yield checkbox_input.CheckboxInput(
                "Commands",
                active=True,
                value=command_field.value,
                placeholder="Type a command",
                id="perm-command-list",
            )

    async def on_mount(self) -> None:
        await self._mount_filter_candidates()
        self.query_one("#perm-username-list", checkbox_input.CheckboxInput).set_candidates([])
        self.query_one("#perm-command-list", checkbox_input.CheckboxInput).set_candidates([])

    def get_grant_data(self) -> pfc.schemas.SSHCommandGrant:
        return pfc.schemas.SSHCommandGrant(
            type="ssh-command",
            filter=self._filter_data(),
            permission=pfc.schemas.SSHCommandPermission(
                username_list=self._read_field("#perm-username-list").boundary_perm(),
                command_list=self._read_field("#perm-command-list").boundary_perm(),
            ),
        )
