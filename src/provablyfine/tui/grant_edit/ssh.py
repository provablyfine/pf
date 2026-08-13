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
        ttl = base.Field(
            active=p.max_session_ttl_s is not None,
            value="" if p.max_session_ttl_s is None else str(p.max_session_ttl_s),
        )
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
                suggester=checkbox_input.RemainingValuesSuggester(_CAPABILITIES),
            )
            yield checkbox_input.CheckboxInput(
                "Commands",
                active=command.active,
                value=command.value,
                placeholder="Type a command",
                id="perm-command-list",
            )
            yield checkbox_input.CheckboxInput(
                "Max session TTL (s)",
                active=ttl.active,
                value=ttl.value,
                placeholder="Seconds, e.g. 3600",
                id="perm-max-session-ttl",
            )

    async def on_mount(self) -> None:
        await self._mount_filter_candidates()
        self.query_one("#perm-username-list", checkbox_input.CheckboxInput).set_candidates([])
        self.query_one("#perm-capability-list", checkbox_input.CheckboxInput).set_candidates(
            [textual_autocomplete.DropdownItem(main=c) for c in _CAPABILITIES]
        )
        self.query_one("#perm-command-list", checkbox_input.CheckboxInput).set_candidates([])
        self.query_one("#perm-max-session-ttl", checkbox_input.CheckboxInput).set_candidates([])

    def get_grant_data(self) -> pfc.schemas.SSHGrant:
        username_list = self._read_field("#perm-username-list").axis_perm()
        capability_list = self._read_field("#perm-capability-list").capability_perm()
        command_list = self._read_field("#perm-command-list").axis_perm()
        max_session_ttl_s = self._read_field("#perm-max-session-ttl").ttl_perm()
        # The same two rules `pfa grant ssh` enforces. The schema tolerates an
        # empty list, because migrated rows may carry one, but an authoring
        # surface should still refuse to write a grant that covers nothing.
        if username_list == []:
            raise pfc.exceptions.UI("Grant has no username. Name one, or uncheck Usernames for any.")
        if capability_list == [] and command_list == []:
            raise pfc.exceptions.UI(
                "Grant is empty. Name a capability or a command, or uncheck one of those boxes for any."
            )
        return pfc.schemas.SSHGrant(
            type="ssh",
            filter=self._filter_data(),
            permission=pfc.schemas.SSHPermission(
                username_list=username_list,
                capability_list=capability_list,
                command_list=command_list,
                max_session_ttl_s=max_session_ttl_s,
            ),
        )
