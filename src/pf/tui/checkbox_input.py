import textual
import textual.app
import textual.message
import textual.widget
import textual.widgets

from . import auto_complete


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

    def __init__(self, label: str, *, active: bool, value: str, placeholder: str, id: str | None = None) -> None:
        super().__init__(id=id)
        self._label = label
        self._active = active
        self._value = value
        self._placeholder = placeholder

    @property
    def active(self) -> bool:
        return self._active

    @property
    def value(self) -> str:
        return self._value

    def compose(self) -> textual.app.ComposeResult:
        inp = textual.widgets.Input(
            value=self._value,
            placeholder=self._placeholder,
            compact=True,
            disabled=not self._active,
        )
        yield textual.widgets.Checkbox(self._label, value=self._active, compact=True)
        yield inp
        yield auto_complete.MultiAutoComplete(inp)

    def set_candidates(self, candidates: list) -> None:
        self.query_one(auto_complete.MultiAutoComplete).candidates = candidates

    @textual.on(textual.widgets.Checkbox.Changed)
    def _on_checkbox_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        event.stop()
        self._active = event.value
        inp = self.query_one(textual.widgets.Input)
        if not event.value:
            inp.clear()
            self._value = ""
        inp.disabled = not event.value
        if event.value:
            inp.focus()
        self.post_message(self.Changed(self, self._active, self._value))

    @textual.on(textual.widgets.Input.Changed)
    def _on_input_changed(self, event: textual.widgets.Input.Changed) -> None:
        event.stop()
        self._value = event.value
        self.post_message(self.Changed(self, self._active, self._value))
