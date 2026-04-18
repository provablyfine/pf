import textual
import textual.app

from ...client import schemas
from .. import checkbox_input
from .base import _Field, _SshBaseGrantEditWidget


class SshShellGrantEditWidget(_SshBaseGrantEditWidget):
    DEFAULT_CSS = """
    SshShellGrantEditWidget {
        height: auto;
    }
    """

    def compose(self) -> textual.app.ComposeResult:
        p = self._grant.permission
        username_field = _Field(active=True, value=" ".join(p.username_list or []))
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
            yield textual.widgets.Checkbox(
                "Permit agent forwarding",
                value=p.permit_agent_forwarding,
                id="perm-permit-agent-forwarding",
                compact=True,
            )
            yield textual.widgets.Checkbox(
                "Permit X11 forwarding",
                value=p.permit_x11_forwarding,
                id="perm-permit-x11-forwarding",
                compact=True,
            )

    async def on_mount(self) -> None:
        await self._mount_filter_candidates()
        self.query_one("#perm-username-list", checkbox_input.CheckboxInput).set_candidates([])

    def get_grant_data(self) -> schemas.SSHShellGrant:
        return schemas.SSHShellGrant(
            type="ssh-shell",
            filter=self._filter_data(),
            permission=schemas.SSHShellPermission(
                username_list=self._read_field("#perm-username-list").boundary_perm(),
                permit_agent_forwarding=self.query_one(
                    "#perm-permit-agent-forwarding", textual.widgets.Checkbox
                ).value,
                permit_x11_forwarding=self.query_one("#perm-permit-x11-forwarding", textual.widgets.Checkbox).value,
            ),
        )
