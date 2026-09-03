import textual.app
import textual.content
import textual.dom
import textual.events
import textual.reactive
import textual.widgets

from . import base


class _HeaderTitle(textual.widgets.Static):
    DEFAULT_CSS = """
    _HeaderTitle {
        text-wrap: nowrap;
        text-overflow: ellipsis;
        content-align: center middle;
        width: 100%;
    }
    """


class _HeaderIdentity(textual.widgets.Static):
    DEFAULT_CSS = """
    _HeaderIdentity {
        dock: right;
        width: auto;
        padding: 0 1;
        content-align: right middle;
    }
    """


class AppHeader(base.Widget):
    """A header widget equivalent to textual's Header, without the command-palette icon."""

    DEFAULT_CSS = """
    AppHeader {
        dock: top;
        width: 100%;
        background: $panel;
        color: $foreground;
        height: 1;
    }
    AppHeader.-tall {
        height: 3;
    }
    """

    tall: textual.reactive.Reactive[bool] = textual.reactive.Reactive(False)

    def compose(self) -> textual.app.ComposeResult:
        yield _HeaderIdentity()
        yield _HeaderTitle()

    def watch_tall(self, tall: bool) -> None:
        self.set_class(tall, "-tall")

    async def _on_click(self, event: textual.events.Click) -> None:
        self.toggle_class("-tall")

    @property
    def screen_title(self) -> str:
        screen_title = self.screen.title
        return screen_title if screen_title is not None else self.app.title

    @property
    def screen_sub_title(self) -> str:
        screen_sub_title = self.screen.sub_title
        return screen_sub_title if screen_sub_title is not None else self.app.sub_title

    def format_title(self) -> textual.content.Content:
        return self.app.format_title(self.screen_title, self.screen_sub_title)

    def on_mount(self) -> None:
        async def set_title() -> None:
            try:
                self.query_one(_HeaderTitle).update(self.format_title())
            except textual.dom.NoScreen:
                pass

        async def set_identity(whoami: str) -> None:
            self.query_one(_HeaderIdentity).update(whoami)

        self.watch(self.app, "title", set_title)
        self.watch(self.app, "sub_title", set_title)
        self.watch(self.screen, "title", set_title)
        self.watch(self.screen, "sub_title", set_title)
        self.watch(self.app, "whoami", set_identity)
