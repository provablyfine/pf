import asyncio

import textual
import textual.app
import textual.containers
import textual.reactive
import textual.screen
import textual.widget
import textual.widgets
import textual_autocomplete

from .. import client
from . import auto_complete


def _update_field(update: dict | None, field: str) -> bool:
    """Return the value of an update permission field.

    When update is None it means all update permissions are granted (wildcard).
    """
    if update is None:
        return True
    return update[field]


def _role_filter_empty():
    return {"name": None}


def _role_permission_empty():
    return {
        "create": False,
        "read": False,
        "update": {
            "name": False,
            "description": False,
            "grant_list": False,
            "member_list": False,
        },
        "delete": False,
    }


def _identity_filter_empty():
    return {
        "name": None,
        "tag_list": None,
        "boundary_list": None,
    }


def _identity_permission_empty():
    return {
        "create": {
            "allowed": False,
            "allowed_tag_list": [],
            "required_boundary_list": None,
        },
        "read": False,
        "update": {
            "name": False,
        },
        "delete": False,
    }


class RoleGrantEditWidget(textual.widget.Widget):
    DEFAULT_CSS = """
    #filter-select-name {
        width: 20;
    }
    RoleGrantEditWidget {
        height: auto;
    }
    #filters {
        height: 1;
        layout: grid;
        grid-size: 2;
        grid-columns: auto 1fr;
        grid-rows: 1fr;
        grid-gutter: 0 2;
    }
    """

    def __init__(self, auth: client.HttpClient, filter, permission):
        super().__init__()
        self._auth = auth
        self._filter = filter
        self._permission = permission

    async def _list_roles(self):
        response = await asyncio.to_thread(self._auth.get, self._auth.directory.role)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of roles"), severity="error")
            return []
        return response.json()["roles"]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            with textual.containers.Container(id="filters"):
                yield textual.widgets.Label("Name is", classes="label")
                yield textual.widgets.Select.from_values(
                    ["*"], compact=True, allow_blank=False, disabled=True, id="filter-select-name"
                )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.SelectionList(
                ("Create", "create", self._permission["create"]),
                ("Read", "read", self._permission["read"]),
                ("Update name", "update.name", _update_field(self._permission["update"], "name")),
                ("Update description", "update.description", _update_field(self._permission["update"], "description")),
                ("Update member list", "update.member_list", _update_field(self._permission["update"], "member_list")),
                ("Update grant list", "update.grant_list", _update_field(self._permission["update"], "grant_list")),
                ("Delete", "delete", self._permission["delete"]),
                compact=True,
            )

    async def on_mount(self) -> None:
        roles = await self._list_roles()
        select = self.query_one("#filter-select-name", textual.widgets.Select)
        select.set_options([("*", None)] + [(f'role "{r["name"]}"', r["id"]) for r in roles])
        select.disabled = False


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
    #permission-create-fields {
        height: 2;
        margin: 0 0 0 3;
        layout: grid;
        grid-size: 2;
        grid-columns: auto 1fr;
        grid-rows: 1fr;
        grid-gutter: 0 2;
    }
    """

    def __init__(self, auth: client.HttpClient, filter, permission):
        super().__init__()
        self._auth = auth
        self._filter = filter
        self._permission = permission

    async def _list_identities(self):
        response = await asyncio.to_thread(self._auth.get, self._auth.directory.identity)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of identities"), severity="error")
            return []
        return response.json()["identities"]

    async def _list_tags(self):
        response = await asyncio.to_thread(self._auth.get, self._auth.directory.tag)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of tags"), severity="error")
            return []
        return response.json()["tags"]

    async def _list_boundaries(self):
        response = await asyncio.to_thread(self._auth.get, self._auth.directory.boundary)
        if response.status_code != 200:
            self.notify(response.json().get("title", "Failed to read list of boundaries"), severity="error")
            return []
        return response.json()["boundaries"]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            with textual.containers.Container(id="filters"):
                yield textual.widgets.Label("Name is", classes="label")
                yield textual.widgets.Select.from_values(
                    ["*"], compact=True, allow_blank=False, disabled=True, id="filter-select-name"
                )
                yield textual.widgets.Label("Tagged by", classes="label")
                tagged_by = textual.widgets.Input(placeholder="Type a tag name=value", compact=True)
                yield tagged_by

                yield textual.widgets.Label("Bounded by", classes="label")
                bounded_by = textual.widgets.Input(placeholder="Type a boundary name", compact=True)
                yield bounded_by
            yield auto_complete.MultiAutoComplete(bounded_by, id="filter-bounded-by-auto-complete")
            yield auto_complete.MultiAutoComplete(tagged_by, id="filter-tagged-by-auto-complete")
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.Checkbox(
                "Create", value=self._permission["create"]["allowed"], id="permission-create", compact=True
            )
            with textual.containers.Container(
                id="permission-create-fields", disabled=not self._permission["create"]["allowed"]
            ):
                yield textual.widgets.Label("Allowed tags", classes="label")
                allowed_tags = textual.widgets.Input(placeholder="Type a tag name=value", compact=True)
                yield allowed_tags
                yield textual.widgets.Label("Required Boundaries", classes="label")
                required_boundaries = textual.widgets.Input(placeholder="Type a boundary name", compact=True)
                yield required_boundaries
            yield textual.widgets.Checkbox("Read", value=self._permission["read"], id="permission-read", compact=True)
            yield textual.widgets.Checkbox(
                "Update", value=_update_field(self._permission["update"], "name"), id="permission-update-name",
                compact=True
            )
            yield textual.widgets.Checkbox(
                "Delete", value=self._permission["delete"], id="permission-delete", compact=True
            )
            yield auto_complete.MultiAutoComplete(
                required_boundaries, id="permission-create-allowed-tags-auto-complete"
            )
            yield auto_complete.MultiAutoComplete(
                allowed_tags, id="permission-create-required-boundaries-auto-complete"
            )

    async def on_mount(self) -> None:
        identities = await self._list_identities()
        select = self.query_one("#filter-select-name", textual.widgets.Select)
        select.set_options([("*", None)] + [(i["name"], i["id"]) for i in identities])
        select.disabled = False

        tags = await self._list_tags()
        tags = [textual_autocomplete.DropdownItem(main=f"{t['name']}={t['value']}") for t in tags]
        tagged_by_auto_complete = self.query_one("#filter-tagged-by-auto-complete", auto_complete.MultiAutoComplete)
        tagged_by_auto_complete.candidates = tags
        allowed_tags_auto_complete = self.query_one(
            "#permission-create-allowed-tags-auto-complete", auto_complete.MultiAutoComplete
        )
        allowed_tags_auto_complete.candidates = tags

        boundaries = await self._list_boundaries()
        boundaries = [textual_autocomplete.DropdownItem(main=b["name"]) for b in boundaries]
        bounded_by_auto_complete = self.query_one("#filter-bounded-by-auto-complete", auto_complete.MultiAutoComplete)
        bounded_by_auto_complete.candidates = boundaries
        required_boundaries_auto_complete = self.query_one(
            "#permission-create-required-boundaries-auto-complete", auto_complete.MultiAutoComplete
        )
        required_boundaries_auto_complete.candidates = boundaries


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

    def __init__(self, auth: client.HttpClient, grant):
        super().__init__(id="grant-edit")
        self._auth = auth
        self.grant_type = grant["type"]
        self._filter = grant["filter"]
        self._permission = grant["permission"]

    async def watch_grant_type(self, value: str) -> None:
        fields = self.query_one("#dynamic-grant-fields")
        await fields.query("*").remove()
        match self.grant_type:
            case "role":
                widget = RoleGrantEditWidget(self._auth, self._filter, self._permission)
            case "identity":
                widget = IdentityGrantEditWidget(self._auth, self._filter, self._permission)
            case _:
                assert False
        await fields.mount(widget)

    @textual.on(textual.widgets.Select.Changed, "#grant-type-select")
    def on_grant_type_changed(self, event: textual.widgets.Select.Changed) -> None:
        self.grant_type = str(event.value)
        match self.grant_type:
            case "role":
                self._filter = _role_filter_empty()
                self._permission = _role_permission_empty()
            case "identity":
                self._filter = _identity_filter_empty()
                self._permission = _identity_permission_empty()

    def compose(self) -> textual.app.ComposeResult:
        self.sub_title = "Roles > 2 > Grants > Edit"
        with textual.containers.VerticalGroup(classes="sections"):
            with textual.containers.VerticalGroup(classes="section"):
                yield textual.widgets.Label("Type", classes="label")
                yield textual.widgets.Select.from_values(
                    ["identity", "tag", "role", "boundary", "tenant"],
                    value=self.grant_type,
                    compact=True,
                    allow_blank=False,
                    id="grant-type-select",
                )
            yield textual.containers.Container(id="dynamic-grant-fields")
