import textual
import textual.app
import textual.containers
import textual.widgets

from ...client import schemas
from .. import checkbox_input
from . import base


class SshPortForwardingGrantEditWidget(base.TripletFilterGrantEditWidget[schemas.SSHPortForwardingGrant]):
    DEFAULT_CSS = """
    SshPortForwardingGrantEditWidget {
        height: auto;
    }
    """

    def compose(self) -> textual.app.ComposeResult:
        p = self._grant.permission
        username_field = base.Field(active=True, value=" ".join(p.username_list or []))
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

    async def on_mount(self) -> None:
        await self._mount_filter_candidates()
        self.query_one("#perm-username-list", checkbox_input.CheckboxInput).set_candidates([])

    def get_grant_data(self) -> schemas.SSHPortForwardingGrant:
        return schemas.SSHPortForwardingGrant(
            type="ssh-port-forwarding",
            filter=self._filter_data(),
            permission=schemas.SSHPortForwardingPermission(
                username_list=self._read_field("#perm-username-list").boundary_perm(),
            ),
        )
