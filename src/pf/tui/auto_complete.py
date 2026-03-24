import textual
import textual_autocomplete

class MultiAutoComplete(textual_autocomplete.AutoComplete):
    DEFAULT_CSS = """\
    MultiAutoComplete {
        height: 5
    }
    """
    def get_search_string(self, state: textual_autocomplete.TargetState) -> str:
        current_input = state.text[:state.cursor_position]
        space = current_input.rfind(" ")
        if space != -1:
            current_input = current_input[space+1:]
        return current_input

    def apply_completion(self, value: str, state: textual_autocomplete.TargetState) -> None:
        space = state.text.rfind(" ", 0, state.cursor_position)
        if space == -1:
            start = 0
        else:
            start = space+1
        new_value = state.text[:start] + value + state.text[state.cursor_position:]
        new_cursor_position = len(state.text[:start] + value)

        with self.prevent(textual.widgets.Input.Changed):
            self.target.value = new_value
            self.target.cursor_position = new_cursor_position

    def get_matches(self,
        target_state: textual_autocomplete.TargetState,
        candidates: list[textual_autocomplete.DropdownItem],
        search_string: str,
    ) -> list[textual_autocomplete.DropdownItem]:
        retval = []
        for candidate in candidates:
            if not candidate.value.startswith(search_string):
                continue
            retval.append(candidate)
        self.styles.height = min(5, len(retval))
        return retval
