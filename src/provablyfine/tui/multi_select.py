import typing

import textual
import textual.app
import textual.binding
import textual.containers
import textual.events
import textual.message
import textual.widgets


class _Popup(textual.widgets.SelectionList[str]):
    """The checklist. It lives under the widget and is drawn over what is below it."""

    BINDINGS: typing.ClassVar = [("escape", "close", "Close"), ("enter", "close", "Close")]

    class Closed(textual.message.Message):
        pass

    def action_close(self) -> None:
        self.post_message(self.Closed())


class MultiSelect(textual.containers.Vertical, can_focus=True):
    """A one-line field that opens a checklist.

    The field reads `title: all` when nothing is checked, and `title: a, b +1` otherwise.
    Nothing is typed. `space`, `enter` or `down` opens the list, `space` checks a value,
    `enter` or `escape` closes it. An empty selection means all.
    """

    DEFAULT_CSS = """
    MultiSelect {
        height: 1;
        width: 1fr;
    }
    MultiSelect > Static {
        height: 1;
        width: 1fr;
        padding: 0 1;
    }
    MultiSelect:focus > Static {
        background: $boost;
    }
    MultiSelect.-edited > Static {
        color: $warning;
    }
    MultiSelect > _Popup {
        display: none;
        width: auto;
        min-width: 100%;
        max-width: 60;
        height: auto;
        max-height: 14;
        overlay: screen;
        constrain: none inside;
        border: tall $primary;
        background: $surface;
    }
    MultiSelect.-expanded > _Popup {
        display: block;
    }
    """
    BINDINGS: typing.ClassVar = [
        textual.binding.Binding("space,down", "open", "Choose", show=False),
        textual.binding.Binding("enter", "submit", "Apply", show=False),
    ]

    class Changed(textual.message.Message):
        def __init__(self, widget: "MultiSelect") -> None:
            super().__init__()
            self.widget = widget

        @property
        def control(self) -> "MultiSelect":
            return self.widget

    class Submitted(textual.message.Message):
        """`enter` on the closed field. It asks the screen to apply the filters."""

        def __init__(self, widget: "MultiSelect") -> None:
            super().__init__()
            self.widget = widget

    def __init__(self, title: str, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self._title = title
        self._options: list[str] = []
        self._selected: list[str] = []

    @property
    def selected(self) -> list[str]:
        """The checked values, in the order of the options."""
        return list(self._selected)

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Static()
        yield _Popup()

    def on_mount(self) -> None:
        self._refresh_label()

    def set_options(self, options: list[str]) -> None:
        """Replace the values on offer. A checked value that is no longer offered is dropped."""
        self._options = list(options)
        self._selected = [v for v in self._selected if v in self._options]
        self._fill_popup()
        self._refresh_label()

    def set_selected(self, values: list[str]) -> None:
        self._selected = [v for v in self._options if v in values]
        self._fill_popup()
        self._refresh_label()

    def set_edited(self, edited: bool) -> None:
        self.set_class(edited, "-edited")

    @property
    def expanded(self) -> bool:
        return self.has_class("-expanded")

    def _popup(self) -> _Popup:
        return self.query_one(_Popup)

    def _fill_popup(self) -> None:
        if not self.is_mounted:
            return
        popup = self._popup()
        highlighted = popup.highlighted
        with popup.prevent(textual.widgets.SelectionList.SelectedChanged):
            popup.clear_options()
            popup.add_options([(v, v, v in self._selected) for v in self._options])
        if highlighted is not None and highlighted < len(self._options):
            popup.highlighted = highlighted

    def _refresh_label(self) -> None:
        if not self.is_mounted:
            return
        if not self._selected:
            value = "all"
        elif len(self._selected) <= 2:
            value = ", ".join(self._selected)
        else:
            value = f"{', '.join(self._selected[:2])} +{len(self._selected) - 2}"
        self.query_one(textual.widgets.Static).update(f"{self._title}: {value} ▾")

    def action_open(self) -> None:
        self.add_class("-expanded")
        popup = self._popup()
        popup.focus()
        if popup.highlighted is None and self._options:
            popup.highlighted = 0

    def action_submit(self) -> None:
        self.post_message(self.Submitted(self))

    def on_click(self, event: textual.events.Click) -> None:
        if not self.expanded:
            self.action_open()

    @textual.on(textual.widgets.SelectionList.SelectedChanged)
    def _on_selected_changed(self, event: textual.widgets.SelectionList.SelectedChanged[str]) -> None:
        event.stop()
        checked = set(self._popup().selected)
        self._selected = [v for v in self._options if v in checked]
        self._refresh_label()
        self.post_message(self.Changed(self))

    @textual.on(_Popup.Closed)
    def _on_closed(self, event: _Popup.Closed) -> None:
        event.stop()
        self.remove_class("-expanded")
        self.focus()

    def on_descendant_blur(self, event: textual.events.DescendantBlur) -> None:
        """Clicking elsewhere closes the list."""
        if self.expanded and not self.has_focus_within:
            self.remove_class("-expanded")
