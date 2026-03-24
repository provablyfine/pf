import asyncio

import textual
import textual_autocomplete


class RoleGrantEditWidget(textual.widget.Widget):
    DEFAULT_CSS = """
    #filter-select-name {
        width: 20;
    }
    RoleGrantEditWidget {
        height: auto;
    }
    """

    def __init__(self, filter, permission):
        super().__init__()
        self._filter = filter
        self._permission = permission

    async def _list_roles(self):
        response = await asyncio.to_thread(self.app.auth.get, self.app.auth.directory.role)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of roles"), severity="error")
            return []
        return response.json()["roles"]

    def compose(self) -> textual.widget.ComposeResult:
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Applied to", classes="label")
            yield textual.widgets.Select.from_values(["all"], compact=True, allow_blank=False, disabled=True, id="filter-select-name")
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Grants", classes="label")
            yield textual.widgets.SelectionList(
                ("Create", "create", self._permission['create']),
                ("Read", "read", self._permission['read']),
                ("Update name", "update.name", self._permission['update']['name']),
                ("Update description", "update.description", self._permission['update']['description']),
                ("Update member list", "update.member_list", self._permission['update']['member_list']),
                ("Update grant list", "update.grant_list", self._permission['update']['grant_list']),
                ("Delete", "delete", self._permission['delete']),
                compact=True
            )

    async def on_mount(self) -> None:
        roles = await self._list_roles()
        select = self.query_one("#filter-select-name")
        select.set_options([("all", None)] + [(f"role \"{r['name']}\"", r["id"]) for r in roles])
        select.disabled = False


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


class IdentityGrantEditWidget(textual.widget.Widget):
    DEFAULT_CSS = """
    IdentityGrantEditWidget {
        height: auto;
    }
    #filters {
        height: 3;
        layout: grid;
        grid-size: 2;
        grid-columns: auto 1fr;
        grid-rows: 1fr;
        grid-gutter: 0 2;
    }
    """

    def __init__(self, filter, permission):
        super().__init__()
        self._filter = filter
        self._permission = permission

    async def _list_identities(self):
        response = await asyncio.to_thread(self.app.auth.get, self.app.auth.directory.identity)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of identities"), severity="error")
            return []
        return response.json()["identities"]

    async def _list_tags(self):
        response = await asyncio.to_thread(self.app.auth.get, self.app.auth.directory.tag)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of tags"), severity="error")
            return []
        return response.json()["tags"]

    async def _list_boundaries(self):
        response = await asyncio.to_thread(self.app.auth.get, self.app.auth.directory.boundary)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of boundaries"), severity="error")
            return []
        return response.json()["boundaries"]

    def compose(self) -> textual.widget.ComposeResult:
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Applied to", classes="label")
            with textual.containers.Container(id="filters"):
                yield textual.widgets.Label("Name is", classes="label")
                yield textual.widgets.Select.from_values(["*"], compact=True, allow_blank=False, disabled=True, id="filter-select-name")
                yield textual.widgets.Label("Tagged by", classes="label")
                tagged_by = textual.widgets.Input(placeholder="Type a tag name=value", compact=True)
                yield tagged_by

                yield textual.widgets.Label("Bounded by", classes="label")
                bounded_by = textual.widgets.Input(placeholder="Type a boundary name", compact=True)
                yield bounded_by
            yield MultiAutoComplete(bounded_by, id="filter-bounded-by-auto-complete")
            yield MultiAutoComplete(tagged_by, id="filter-tagged-by-auto-complete")

    async def on_mount(self) -> None:
        identities = await self._list_identities()
        select = self.query_one("#filter-select-name")
        select.set_options([("*", None)] + [(i["name"], i["id"]) for i in identities])
        select.disabled = False

        tags = await self._list_tags()
        tagged_by_auto_complete = self.query_one("#filter-tagged-by-auto-complete")
        tagged_by_auto_complete.candidates = [textual_autocomplete.DropdownItem(main=f"{t['name']}={t['value']}") for t in tags]

        boundaries = await self._list_boundaries()
        bounded_by_auto_complete = self.query_one("#filter-bounded-by-auto-complete")
        bounded_by_auto_complete.candidates = [textual_autocomplete.DropdownItem(main=b["name"]) for b in boundaries]



class GrantEditScreen(textual.screen.Screen[None]):
    DEFAULT_CSS = """
    .sections {
        padding: 0 1;
    }
    .section {
        padding: 1 0 0 0;
    }
    .label {
        padding: 0 0;
    }
    #grant-type-select {
        width: 12;
    }
    #filter-select-name {
        width: 20;
    }
    """
    grant_type: textual.reactive.Reactive[str] = textual.reactive.Reactive("")

    def __init__(self, grant):
        super().__init__(id="grant-edit")
        self.grant_type = grant['type']
        self._filter = grant['filter']
        self._permission = grant['permission']

    async def watch_grant_type(self, value: str) -> None:
        fields = self.query_one("#dynamic-grant-fields")
        await fields.query("*").remove()
        match self.grant_type:
            case 'role':
                widget = RoleGrantEditWidget(self._filter, self._permission)
            case 'identity':
                widget = IdentityGrantEditWidget(self._filter, self._permission)
            case _:
                assert False
        await fields.mount(widget)


    @textual.on(textual.widgets.Select.Changed, "#grant-type-select")
    def on_grant_type_changed(self, event: textual.widgets.Select.Changed) -> None:
        self.grant_type = str(event.value)

    def compose(self) -> textual.widget.ComposeResult:
        self.sub_title = 'Roles > 2 > Grants > Edit'
        with textual.containers.VerticalGroup(classes="sections"):
            with textual.containers.VerticalGroup(classes="section"):
                yield textual.widgets.Label("Type", classes="label")
                yield textual.widgets.Select.from_values(
                    ["identity", "tag", "role", "boundary", "tenant"],
                    value=self.grant_type,
                    compact=True,
                    allow_blank=False,
                    id="grant-type-select"
                )
            yield textual.containers.Container(id="dynamic-grant-fields")
