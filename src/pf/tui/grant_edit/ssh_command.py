import textual
import textual.app

from .. import checkbox_input
from .base import _Field, _SshBaseGrantEditWidget


class SshCommandGrantEditWidget(_SshBaseGrantEditWidget):
    DEFAULT_CSS = """
    SshCommandGrantEditWidget {
        height: auto;
    }
    """

    def compose(self) -> textual.app.ComposeResult:
        f = self._initial_filter
        p = self._initial_permission
        username_field = _Field(active=True, value=" ".join(p.get("username_list") or []))
        command_field = _Field(active=True, value=" ".join(p.get("command_list") or []))
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

    def get_grant_data(self) -> tuple[dict, dict]:
        return (
            self._filter_data(),
            {
                "username_list": self._read_field("#perm-username-list").boundary_perm(),
                "command_list": self._read_field("#perm-command-list").boundary_perm(),
            },
        )
