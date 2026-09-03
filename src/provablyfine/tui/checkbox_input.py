import textual
import textual.app
import textual.events
import textual.message
import textual.suggester
import textual.widget
import textual.widgets
import textual.widgets.input
import textual_autocomplete

from . import auto_complete


class RemainingValuesSuggester(textual.suggester.Suggester):
    """Greys out the values of a closed set that the field does not use yet.

    The placeholder names the whole set, but only while the field is empty.
    This carries that on: once something is typed, what is left of the set is
    rendered dim after it.
    """

    def __init__(self, values: list[str]) -> None:
        super().__init__(case_sensitive=True)
        self._values = values

    async def get_suggestion(self, value: str) -> str | None:
        used = value.split()
        # Mid-token: the autocomplete dropdown is completing it, and a list
        # spliced onto a half-typed word would just read as garbage.
        if value and not value[-1].isspace() and used[-1] not in self._values:
            return None
        remaining = [v for v in self._values if v not in used]
        if not remaining:
            return None
        separator = "" if not value or value[-1].isspace() else " "
        return value + separator + " ".join(remaining)


class _HintInput(textual.widgets.Input):
    """Input whose suggestion is a hint rather than a completion.

    `Input` turns `right` at the end of the line into "accept the whole
    suggestion". Here the suggestion is the list of values still available,
    so accepting it would fill the field with every one of them.
    """

    def _on_focus(self, event: textual.events.Focus) -> None:
        super()._on_focus(event)
        # `Input` asks the suggester only when the value changes, renders a
        # suggestion only while focused, and drops the one it has on focus.
        # A field the user has not typed in yet would therefore never show a
        # hint: ask again here, the way the value watcher does.
        if self.suggester is not None and self.value:
            self.run_worker(self.suggester._get_suggestion(self, self.value))  # pyright: ignore[reportPrivateUsage]

    def action_cursor_right(self, select: bool = False) -> None:
        start, end = self.selection
        if select:
            self.selection = textual.widgets.input.Selection(start, end + 1)
        elif self.selection.is_empty:
            self.cursor_position += 1
        else:
            self.cursor_position = max(start, end)


class CheckboxInput(textual.widget.Widget):
    """A checkbox that gates an Input field with autocomplete.

    Unchecked: field disabled and cleared, active=False.
    Checked: field enabled, active=True, value is editable.
    Emits CheckboxInput.Changed instead of letting Checkbox.Changed and
    Input.Changed bubble up.
    """

    DEFAULT_CSS = """
    CheckboxInput {
        column-span: 2;
        layout: grid;
        grid-size: 2;
        grid-columns: auto 1fr;
        grid-gutter: 0 2;
        height: 1;
    }
    """

    class Changed(textual.message.Message):
        def __init__(self, widget: "CheckboxInput", active: bool, value: str) -> None:
            super().__init__()
            self.widget = widget
            self.active = active
            self.value = value

        @property
        def control(self) -> "CheckboxInput":
            return self.widget

    def __init__(
        self,
        label: str,
        *,
        active: bool,
        value: str,
        placeholder: str,
        id: str | None = None,
        autocomplete: type[textual_autocomplete.AutoComplete] = auto_complete.MultiAutoComplete,
        suggester: textual.suggester.Suggester | None = None,
    ) -> None:
        super().__init__(id=id)
        self._label = label
        self._active = active
        self._initial_value = value
        self._placeholder = placeholder
        self._autocomplete_class = autocomplete
        self._suggester = suggester
        self._autocomplete: textual_autocomplete.AutoComplete | None = None

    @property
    def active(self) -> bool:
        return self._active

    @property
    def value(self) -> str:
        return self.query_one(textual.widgets.Input).value

    def compose(self) -> textual.app.ComposeResult:
        inp = _HintInput(
            value=self._initial_value,
            placeholder=self._placeholder,
            compact=True,
            disabled=not self._active,
            suggester=self._suggester,
            # These fields hold a value the user comes back to extend, not one
            # they retype. Selecting it on focus would make the next keystroke
            # replace the whole list.
            select_on_focus=False,
        )
        yield textual.widgets.Checkbox(self._label, value=self._active, compact=True)
        yield inp

    def on_mount(self) -> None:
        inp = self.query_one(textual.widgets.Input)
        self._autocomplete = self._autocomplete_class(inp)
        self.screen.mount(self._autocomplete)

    def on_unmount(self) -> None:
        if self._autocomplete is not None:
            self._autocomplete.remove()
            self._autocomplete = None

    def set_candidates(self, candidates: list[textual_autocomplete.DropdownItem]) -> None:
        if self._autocomplete is not None:
            self._autocomplete.candidates = candidates

    @textual.on(textual.widgets.Checkbox.Changed)
    def _on_checkbox_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        event.stop()
        self._active = event.value
        inp = self.query_one(textual.widgets.Input)
        if not event.value:
            inp.clear()
        inp.disabled = not event.value
        if event.value:
            inp.focus()
        self.post_message(self.Changed(self, self._active, inp.value))

    @textual.on(textual.widgets.Input.Changed)
    def _on_input_changed(self, event: textual.widgets.Input.Changed) -> None:
        event.stop()
        self.post_message(self.Changed(self, self._active, event.value))
