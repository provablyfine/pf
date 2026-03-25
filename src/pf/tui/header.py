from textual import events
from textual.app import ComposeResult
from textual.content import Content
from textual.dom import NoScreen
from textual.reactive import Reactive
from textual.widget import Widget
from textual.widgets import Static


class _HeaderTitle(Static):
    DEFAULT_CSS = """
    _HeaderTitle {
        text-wrap: nowrap;
        text-overflow: ellipsis;
        content-align: center middle;
        width: 100%;
    }
    """


class AppHeader(Widget):
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

    tall: Reactive[bool] = Reactive(False)

    def compose(self) -> ComposeResult:
        yield _HeaderTitle()

    def watch_tall(self, tall: bool) -> None:
        self.set_class(tall, "-tall")

    async def _on_click(self, event: events.Click) -> None:
        self.toggle_class("-tall")

    @property
    def screen_title(self) -> str:
        screen_title = self.screen.title
        return screen_title if screen_title is not None else self.app.title

    @property
    def screen_sub_title(self) -> str:
        screen_sub_title = self.screen.sub_title
        return screen_sub_title if screen_sub_title is not None else self.app.sub_title

    def format_title(self) -> Content:
        return self.app.format_title(self.screen_title, self.screen_sub_title)

    def on_mount(self) -> None:
        async def set_title() -> None:
            try:
                self.query_one(_HeaderTitle).update(self.format_title())
            except NoScreen:
                pass

        self.watch(self.app, "title", set_title)
        self.watch(self.app, "sub_title", set_title)
        self.watch(self.screen, "title", set_title)
        self.watch(self.screen, "sub_title", set_title)
