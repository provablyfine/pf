import textual
import textual.widgets
import textual_autocomplete


class MonoAutoComplete(textual_autocomplete.AutoComplete):
    """AutoComplete for a single-value input: searches the full text, replaces the full value."""

    DEFAULT_CSS = """\
    MonoAutoComplete {
        height: 5
    }
    """

    def get_search_string(self, target_state: textual_autocomplete.TargetState) -> str:
        return target_state.text[: target_state.cursor_position]

    def apply_completion(self, value: str, state: textual_autocomplete.TargetState) -> None:
        with self.prevent(textual.widgets.Input.Changed):
            self.target.value = value
            self.target.cursor_position = len(value)

    def get_matches(
        self,
        target_state: textual_autocomplete.TargetState,
        candidates: list[textual_autocomplete.DropdownItem],
        search_string: str,
    ) -> list[textual_autocomplete.DropdownItem]:
        if not search_string:
            self.styles.height = 0
            return []
        retval = [c for c in candidates if search_string in c.value]
        self.styles.height = min(5, len(retval))
        return retval


class MultiAutoComplete(textual_autocomplete.AutoComplete):
    DEFAULT_CSS = """\
    MultiAutoComplete {
        height: 5
    }
    """

    def get_search_string(self, target_state: textual_autocomplete.TargetState) -> str:
        current_input = target_state.text[: target_state.cursor_position]
        space = current_input.rfind(" ")
        if space != -1:
            current_input = current_input[space + 1 :]
        return current_input

    def apply_completion(self, value: str, state: textual_autocomplete.TargetState) -> None:
        space = state.text.rfind(" ", 0, state.cursor_position)
        if space == -1:
            start = 0
        else:
            start = space + 1
        new_value = state.text[:start] + value + state.text[state.cursor_position :]
        new_cursor_position = len(state.text[:start] + value)

        with self.prevent(textual.widgets.Input.Changed):
            self.target.value = new_value
            self.target.cursor_position = new_cursor_position

    def get_matches(
        self,
        target_state: textual_autocomplete.TargetState,
        candidates: list[textual_autocomplete.DropdownItem],
        search_string: str,
    ) -> list[textual_autocomplete.DropdownItem]:
        if not search_string:
            self.styles.height = 0
            return []
        retval = [c for c in candidates if c.value.startswith(search_string)]
        self.styles.height = min(5, len(retval))
        return retval
