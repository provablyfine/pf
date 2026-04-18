import textual
import textual.app

from .. import checkbox_input
from .base import _Field, _SshBaseGrantEditWidget


class SshPortForwardingGrantEditWidget(_SshBaseGrantEditWidget):
    DEFAULT_CSS = """
    SshPortForwardingGrantEditWidget {
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

    async def on_mount(self) -> None:
        await self._mount_filter_candidates()
        self.query_one("#perm-username-list", checkbox_input.CheckboxInput).set_candidates([])

    def get_grant_data(self) -> tuple[dict, dict]:
        return (
            self._filter_data(),
            {"username_list": self._read_field("#perm-username-list").boundary_perm()},
        )
