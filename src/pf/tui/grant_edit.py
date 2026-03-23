import asyncio

import textual


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
            yield textual.widgets.Label("Applies to", classes="label")
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
        ["all"] + [r["name"] for r in roles]
        select = self.query_one("#filter-select-name")
        select.set_options([("all", None)] + [(f"role \"{r['name']}\"", r["id"]) for r in roles])
        select.disabled = False


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
