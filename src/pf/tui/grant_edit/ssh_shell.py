import textual
import textual.app

from .. import checkbox_input
from .base import _Field, _SshBaseGrantEditWidget


class SshShellGrantEditWidget(_SshBaseGrantEditWidget):
    DEFAULT_CSS = """
    SshShellGrantEditWidget {
        height: auto;
    }
    """

    def compose(self) -> textual.app.ComposeResult:
        f = self._initial_filter
        p = self._initial_permission
        username_field = _Field(active=True, value=" ".join(p.get("username_list") or []))
        yield from self._compose_filter(f)
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
                value=p.get("permit_agent_forwarding", False),
                id="perm-permit-agent-forwarding",
                compact=True,
            )
            yield textual.widgets.Checkbox(
                "Permit X11 forwarding",
                value=p.get("permit_x11_forwarding", False),
                id="perm-permit-x11-forwarding",
                compact=True,
            )

    async def on_mount(self) -> None:
        await self._mount_filter_candidates()
        self.query_one("#perm-username-list", checkbox_input.CheckboxInput).set_candidates([])

    def get_grant_data(self) -> tuple[dict, dict]:
        return (
            self._filter_data(),
            {
                "username_list": self._read_field("#perm-username-list").boundary_perm(),
                "permit_agent_forwarding": self.query_one(
                    "#perm-permit-agent-forwarding", textual.widgets.Checkbox
                ).value,
                "permit_x11_forwarding": self.query_one("#perm-permit-x11-forwarding", textual.widgets.Checkbox).value,
            },
        )
