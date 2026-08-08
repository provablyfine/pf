import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets
import textual_autocomplete

from .. import checkbox_input
from . import base

_CAPABILITIES = [c.value for c in pfc.schemas.SSHCapability]


class SshGrantEditWidget(base.TripletFilterGrantEditWidget[pfc.schemas.SSHGrant]):
    DEFAULT_CSS = """
    SshGrantEditWidget {
        height: auto;
    }
    """

    def compose(self) -> textual.app.ComposeResult:
        p = self._grant.permission
        # An unchecked box is the whole axis: any username, every capability,
        # any command. That is what null means in the stored grant.
        username = base.Field.from_axis(p.username_list)
        capability = base.Field.from_axis(p.capability_list)
        command = base.Field.from_axis(p.command_list)
        yield from self._compose_filter()
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions (unchecked = any)", classes="label")
            yield checkbox_input.CheckboxInput(
                "Usernames",
                active=username.active,
                value=username.value,
                placeholder="Type a username",
                id="perm-username-list",
            )
            yield checkbox_input.CheckboxInput(
                "Capabilities",
                active=capability.active,
                value=capability.value,
                placeholder=" ".join(_CAPABILITIES),
                id="perm-capability-list",
            )
            yield checkbox_input.CheckboxInput(
                "Commands",
                active=command.active,
                value=command.value,
                placeholder="Type a command",
                id="perm-command-list",
            )

    async def on_mount(self) -> None:
        await self._mount_filter_candidates()
        self.query_one("#perm-username-list", checkbox_input.CheckboxInput).set_candidates([])
        self.query_one("#perm-capability-list", checkbox_input.CheckboxInput).set_candidates(
            [textual_autocomplete.DropdownItem(main=c) for c in _CAPABILITIES]
        )
        self.query_one("#perm-command-list", checkbox_input.CheckboxInput).set_candidates([])

    def get_grant_data(self) -> pfc.schemas.SSHGrant:
        return pfc.schemas.SSHGrant(
            type="ssh",
            filter=self._filter_data(),
            permission=pfc.schemas.SSHPermission(
                username_list=self._read_field("#perm-username-list").axis_perm(),
                capability_list=self._read_field("#perm-capability-list").capability_perm(),
                command_list=self._read_field("#perm-command-list").axis_perm(),
            ),
        )
