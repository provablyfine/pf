import textual
import textual.app
import textual.containers
import textual.message
import textual.widget
import textual.widgets


class _ValueRow(textual.widgets.Input):
    """One value of the list, on its own line.

    Enter opens a line below, backspace on an empty line closes it: the two
    keys a text field already trains the user to press, so the list needs no
    key of its own. `ctrl+d` would have been the obvious third, and `Input`
    has already spent it on delete_right.
    """

    class RemoveRequested(textual.message.Message):
        def __init__(self, row: "_ValueRow") -> None:
            super().__init__()
            self.row = row

    def action_delete_left(self) -> None:
        # `Input` binds backspace here. On an empty row there is no character
        # left to delete, so the keystroke means "drop this line" instead.
        if self.value:
            super().action_delete_left()
            return
        self.post_message(self.RemoveRequested(self))


class CheckboxList(textual.widget.Widget):
    """A checkbox that gates a vertical list of one-line values.

    Unchecked: rows disabled, active=False. Checked: rows editable,
    active=True, one row per value.

    The sibling of `CheckboxInput` for values that may contain spaces. An SSH
    command is one exact string — the server looks the whole thing up and the
    certificate carries the whole thing as force_command — so it cannot share
    a field that means "split me on whitespace".
    """

    DEFAULT_CSS = """
    CheckboxList {
        layout: grid;
        grid-size: 2;
        grid-columns: auto 1fr;
        grid-gutter: 0 2;
        height: auto;
    }
    """

    def __init__(
        self,
        label: str,
        *,
        active: bool,
        values: list[str],
        placeholder: str,
        id: str | None = None,
    ) -> None:
        super().__init__(id=id)
        self._label = label
        self._active = active
        self._initial_values = values
        self._placeholder = placeholder
        self._row_count = 0

    @property
    def active(self) -> bool:
        return self._active

    @property
    def values(self) -> list[str]:
        """A blank row is not a value: an empty string here would be a command
        named "" that the grant would then have to carry and match on.
        """
        return [text for row in self._rows() if (text := row.value.strip())]

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Checkbox(self._label, value=self._active, compact=True)
        # A checked field with no value still needs a line to type on: a new
        # ssh grant starts at command_list=[].
        with textual.containers.VerticalGroup():
            for value in self._initial_values or [""]:
                yield self._new_row(value)

    def _rows(self) -> list[_ValueRow]:
        return list(self.query(_ValueRow))

    def _new_row(self, value: str = "") -> _ValueRow:
        # A widget's id cannot be reassigned, so row ids count up instead of
        # naming a position that an insertion above would shift.
        row_id = None if self.id is None else f"{self.id}-{self._row_count}"
        self._row_count += 1
        return _ValueRow(
            value=value,
            placeholder=self._placeholder,
            compact=True,
            disabled=not self._active,
            # A row holds a value the user comes back to extend, not one they
            # retype: selecting it on focus would make the next keystroke
            # replace a whole command, and the one after that delete the row.
            select_on_focus=False,
            id=row_id,
        )

    @textual.on(textual.widgets.Checkbox.Changed)
    def _on_checkbox_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        event.stop()
        self._active = event.value
        rows = self._rows()
        # Disabled, not cleared. `CheckboxInput` clears because its value is
        # read straight off the Input, while here the read path already
        # returns null for an inactive field whatever the rows hold. Clearing
        # would let a stray space on the checkbox destroy every command.
        for row in rows:
            row.disabled = not event.value
        if event.value and rows:
            rows[0].focus()

    @textual.on(textual.widgets.Input.Submitted)
    async def _on_input_submitted(self, event: textual.widgets.Input.Submitted) -> None:
        event.stop()
        row = self._new_row()
        await self.query_one(textual.containers.VerticalGroup).mount(row, after=event.input)
        row.focus()

    @textual.on(textual.widgets.Input.Changed)
    def _on_input_changed(self, event: textual.widgets.Input.Changed) -> None:
        # The rows are an implementation detail of this widget, as in
        # `CheckboxInput`: what a single row now holds is nobody else's event.
        event.stop()

    @textual.on(_ValueRow.RemoveRequested)
    async def _on_remove_requested(self, event: _ValueRow.RemoveRequested) -> None:
        event.stop()
        rows = self._rows()
        # The last row is the only place left to type: emptying it is as far
        # as backspace goes. Held-down backspace can queue a second request
        # behind a removal that has not completed, so this counts the rows
        # that are still mounted, not the ones that were when the key landed.
        if len(rows) == 1 or event.row not in rows:
            return
        index = rows.index(event.row)
        # Above the first row there is nothing to fall back to, so it hands
        # focus down rather than making the key do nothing.
        target = rows[index - 1] if index else rows[1]
        target.focus()
        await event.row.remove()
        target.cursor_position = len(target.value) if index else 0
