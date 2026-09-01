import typing

import textual
import textual.app
import textual.containers
import textual.widgets
import textual_autocomplete

from . import auto_complete, base


class MemberAddScreen(base.ModalScreen[str | None]):
    DEFAULT_CSS = """
    MemberAddScreen > VerticalGroup {
        width: 40;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, identity_names: list[str]) -> None:
        super().__init__()
        self._identity_names = identity_names

    def compose(self) -> textual.app.ComposeResult:
        candidates = [textual_autocomplete.DropdownItem(main=n) for n in self._identity_names]
        with textual.containers.VerticalGroup():
            yield base.Input(placeholder="name", compact=True, id="member-name")
        yield auto_complete.MonoAutoComplete("#member-name", candidates=candidates)

    def on_mount(self) -> None:
        self.query_one(textual.containers.VerticalGroup).border_title = "Add member"

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        name = self.query_one(textual.widgets.Input).value.strip()
        if not name:
            return
        self.dismiss(name)
