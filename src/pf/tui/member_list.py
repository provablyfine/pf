import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.suggester
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
            yield textual.widgets.Input(
                placeholder="name",
                suggester=textual.suggester.SuggestFromList(self._identity_names, case_sensitive=False),
                compact=True,
            )

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
