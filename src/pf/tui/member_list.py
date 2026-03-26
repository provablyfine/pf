import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets


class MemberAddScreen(textual.screen.ModalScreen[str | None]):
    DEFAULT_CSS = """
    MemberAddScreen {
        align: center middle;
    }
    MemberAddScreen > VerticalGroup {
        width: 40;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, identity_names: list[str]) -> None:
        super().__init__()
        self._identity_names = identity_names

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup():
            yield textual.widgets.Label("Add member")
            yield textual.widgets.Select.from_values(self._identity_names, allow_blank=True, compact=True)
            yield textual.widgets.Button("Add", variant="primary")

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Button.Pressed)
    def _on_add(self) -> None:
        select = self.query_one(textual.widgets.Select)
        if select.value is textual.widgets.Select.BLANK:
            return
        self.dismiss(str(select.value))
