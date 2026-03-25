import dataclasses
import typing

import textual
import textual.app
import textual.containers
import textual.reactive
import textual.screen
import textual.widget
import textual.widgets
import textual_autocomplete

from . import async_client, checkbox_input


@dataclasses.dataclass
class _Field:
    active: bool
    value: str

    def to_tag_list(self, inactive: list | None) -> list | None:
        if not self.active:
            return inactive
        items = [s.split("=", 1) for s in self.value.split() if "=" in s]
        return [{"name": k, "value": v} for k, v in items]

    def to_boundary_list(self, inactive: list | None) -> list | None:
        if not self.active:
            return inactive
        return self.value.split()

    def to_invite_list(self) -> list[str] | None:
        if not self.active:
            return []
        return [s for s in self.value.split() if s in ("email", "manual")]

    @classmethod
    def from_tag_list(cls, tag_list: list | None) -> "_Field":
        return cls(
            active=tag_list is not None,
            value=" ".join(f"{t['name']}={t['value']}" for t in (tag_list or [])),
        )

    @classmethod
    def from_boundary_list(cls, boundary_list: list[str] | None) -> "_Field":
        return cls(
            active=boundary_list is not None,
            value=" ".join(boundary_list or []),
        )

    @classmethod
    def from_invite_list(cls, invite_list: list[str] | None) -> "_Field":
        return cls(
            active=invite_list is not None,
            value=" ".join(invite_list or []),
        )


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
        "add_tag_list": None,
        "del_tag_list": None,
        "invite_list": None,
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

    def __init__(self, auth: async_client.AsyncClient, filter: dict, permission: dict):
        super().__init__()
        self._auth = auth
        self._filter_name: object = filter["name"]
        self._filter_name_active: bool = filter["name"] is not None
        self._perm_create: bool = permission["create"]
        self._perm_read: bool = permission["read"]
        self._perm_update_name: bool = _update_field(permission["update"], "name")
        self._perm_update_description: bool = _update_field(permission["update"], "description")
        self._perm_update_member_list: bool = _update_field(permission["update"], "member_list")
        self._perm_update_grant_list: bool = _update_field(permission["update"], "grant_list")
        self._perm_delete: bool = permission["delete"]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            with textual.containers.Container(id="filters"):
                yield textual.widgets.Checkbox(
                    "Name", value=self._filter_name_active, compact=True, id="filter-name-active"
                )
                yield textual.widgets.Select.from_values(
                    [], compact=True, allow_blank=True, disabled=True, id="filter-select-name"
                )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.SelectionList(
                ("Create", "create", self._perm_create),
                ("Read", "read", self._perm_read),
                ("Update name", "update.name", self._perm_update_name),
                ("Update description", "update.description", self._perm_update_description),
                ("Update member list", "update.member_list", self._perm_update_member_list),
                ("Update grant list", "update.grant_list", self._perm_update_grant_list),
                ("Delete", "delete", self._perm_delete),
                compact=True,
            )

    async def on_mount(self) -> None:
        roles = await self._auth.list_roles()
        select = self.query_one("#filter-select-name", textual.widgets.Select)
        select.set_options([(r["name"], r["name"]) for r in roles])
        if self._filter_name_active and self._filter_name is not None:
            select.value = self._filter_name
        select.disabled = not self._filter_name_active

    @textual.on(textual.widgets.Checkbox.Changed, "#filter-name-active")
    def _on_filter_name_active_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self._filter_name_active = event.value
        select = self.query_one("#filter-select-name", textual.widgets.Select)
        if not event.value:
            select.clear()
            self._filter_name = None
        select.disabled = not event.value

    @textual.on(textual.widgets.Select.Changed, "#filter-select-name")
    def _on_filter_name_changed(self, event: textual.widgets.Select.Changed) -> None:
        if event.value is not textual.widgets.Select.BLANK:
            self._filter_name = event.value

    @textual.on(textual.widgets.SelectionList.SelectedChanged)
    def _on_selection_changed(self, event: textual.widgets.SelectionList.SelectedChanged) -> None:
        selected = set(event.selection_list.selected)
        self._perm_create = "create" in selected
        self._perm_read = "read" in selected
        self._perm_update_name = "update.name" in selected
        self._perm_update_description = "update.description" in selected
        self._perm_update_member_list = "update.member_list" in selected
        self._perm_update_grant_list = "update.grant_list" in selected
        self._perm_delete = "delete" in selected

    def get_grant_data(self) -> tuple[dict, dict]:
        return (
            {"name": self._filter_name if self._filter_name_active else None},
            {
                "create": self._perm_create,
                "read": self._perm_read,
                "update": {
                    "name": self._perm_update_name,
                    "description": self._perm_update_description,
                    "member_list": self._perm_update_member_list,
                    "grant_list": self._perm_update_grant_list,
                },
                "delete": self._perm_delete,
            },
        )


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
        layout: grid;
        grid-size: 2;
        grid-columns: auto 1fr;
        grid-rows: 1fr;
        grid-gutter: 0 2;
    }
    """

    def __init__(self, auth: async_client.AsyncClient, filter: dict, permission: dict):
        super().__init__()
        self._auth = auth
        self._filter_name: object = filter["name"]
        self._filter_name_active: bool = filter["name"] is not None
        self._filter_tag_list = _Field.from_tag_list(filter.get("tag_list"))
        self._filter_boundary_list = _Field.from_boundary_list(filter.get("boundary_list"))
        self._perm_create_allowed: bool = permission["create"]["allowed"]
        self._perm_create_allowed_tags = _Field.from_tag_list(permission["create"].get("allowed_tag_list") or None)
        self._perm_create_req_boundaries = _Field.from_boundary_list(permission["create"].get("required_boundary_list"))
        self._perm_read: bool = permission["read"]
        self._perm_update_name: bool = _update_field(permission["update"], "name")
        self._perm_delete: bool = permission["delete"]
        self._perm_add_tag_list = _Field.from_tag_list(permission.get("add_tag_list"))
        self._perm_del_tag_list = _Field.from_tag_list(permission.get("del_tag_list"))
        self._perm_invite_list = _Field.from_invite_list(permission.get("invite_list"))

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            with textual.containers.Container(id="filters"):
                yield textual.widgets.Checkbox(
                    "Name", value=self._filter_name_active, compact=True, id="filter-name-active"
                )
                yield textual.widgets.Select.from_values(
                    [], compact=True, allow_blank=True, disabled=True, id="filter-select-name"
                )
                yield checkbox_input.CheckboxInput(
                    "Tagged by",
                    active=self._filter_tag_list.active,
                    value=self._filter_tag_list.value,
                    placeholder="Type a tag name=value",
                    id="filter-tagged-by",
                )
                yield checkbox_input.CheckboxInput(
                    "Bounded by",
                    active=self._filter_boundary_list.active,
                    value=self._filter_boundary_list.value,
                    placeholder="Type a boundary name",
                    id="filter-bounded-by",
                )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.Checkbox(
                "Create", value=self._perm_create_allowed, id="permission-create", compact=True
            )
            with textual.containers.Container(id="permission-create-fields", disabled=not self._perm_create_allowed):
                yield checkbox_input.CheckboxInput(
                    "Create allowed tags",
                    active=self._perm_create_allowed_tags.active,
                    value=self._perm_create_allowed_tags.value,
                    placeholder="Type a tag name=value",
                    id="permission-create-allowed-tags",
                )
                yield checkbox_input.CheckboxInput(
                    "Create required boundaries",
                    active=self._perm_create_req_boundaries.active,
                    value=self._perm_create_req_boundaries.value,
                    placeholder="Type a boundary name",
                    id="permission-create-req-boundaries",
                )
            yield textual.widgets.Checkbox("Read", value=self._perm_read, id="permission-read", compact=True)
            yield textual.widgets.Checkbox(
                "Update", value=self._perm_update_name, id="permission-update-name", compact=True
            )
            yield textual.widgets.Checkbox("Delete", value=self._perm_delete, id="permission-delete", compact=True)
            yield checkbox_input.CheckboxInput(
                "Add tag",
                active=self._perm_add_tag_list.active,
                value=self._perm_add_tag_list.value,
                placeholder="Type a tag name=value",
                id="permission-add-tag",
            )
            yield checkbox_input.CheckboxInput(
                "Del tag",
                active=self._perm_del_tag_list.active,
                value=self._perm_del_tag_list.value,
                placeholder="Type a tag name=value",
                id="permission-del-tag",
            )
            yield checkbox_input.CheckboxInput(
                "Invite",
                active=self._perm_invite_list.active,
                value=self._perm_invite_list.value,
                placeholder="email manual",
                id="permission-invite",
            )

    async def on_mount(self) -> None:
        identities = await self._auth.list_identities()
        select = self.query_one("#filter-select-name", textual.widgets.Select)
        select.set_options([(i["name"], i["name"]) for i in identities])
        if self._filter_name_active and self._filter_name is not None:
            select.value = self._filter_name
        select.disabled = not self._filter_name_active

        tags_raw = await self._auth.list_tags()
        tags = [textual_autocomplete.DropdownItem(main=f"{t['name']}={t['value']}") for t in tags_raw]
        self.query_one("#filter-tagged-by", checkbox_input.CheckboxInput).set_candidates(tags)
        self.query_one("#permission-create-allowed-tags", checkbox_input.CheckboxInput).set_candidates(tags)
        self.query_one("#permission-add-tag", checkbox_input.CheckboxInput).set_candidates(tags)
        self.query_one("#permission-del-tag", checkbox_input.CheckboxInput).set_candidates(tags)

        boundaries_raw = await self._auth.list_boundaries()
        boundaries = [textual_autocomplete.DropdownItem(main=b["name"]) for b in boundaries_raw]
        self.query_one("#filter-bounded-by", checkbox_input.CheckboxInput).set_candidates(boundaries)
        self.query_one("#permission-create-req-boundaries", checkbox_input.CheckboxInput).set_candidates(boundaries)

        invite_methods = [textual_autocomplete.DropdownItem(main=m) for m in ("email", "manual")]
        self.query_one("#permission-invite", checkbox_input.CheckboxInput).set_candidates(invite_methods)

    @textual.on(textual.widgets.Select.Changed, "#filter-select-name")
    def _on_filter_name_changed(self, event: textual.widgets.Select.Changed) -> None:
        if event.value is not textual.widgets.Select.BLANK:
            self._filter_name = event.value

    @textual.on(textual.widgets.Checkbox.Changed, "#filter-name-active")
    def _on_filter_name_active_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self._filter_name_active = event.value
        select = self.query_one("#filter-select-name", textual.widgets.Select)
        if not event.value:
            select.clear()
            self._filter_name = None
        select.disabled = not event.value

    @textual.on(checkbox_input.CheckboxInput.Changed, "#filter-tagged-by")
    def _on_filter_tagged_by_changed(self, event: checkbox_input.CheckboxInput.Changed) -> None:
        self._filter_tag_list = _Field(event.active, event.value)

    @textual.on(checkbox_input.CheckboxInput.Changed, "#filter-bounded-by")
    def _on_filter_bounded_by_changed(self, event: checkbox_input.CheckboxInput.Changed) -> None:
        self._filter_boundary_list = _Field(event.active, event.value)

    @textual.on(textual.widgets.Checkbox.Changed, "#permission-create")
    def _on_perm_create_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self._perm_create_allowed = event.value
        self.query_one("#permission-create-fields").disabled = not event.value

    @textual.on(checkbox_input.CheckboxInput.Changed, "#permission-create-allowed-tags")
    def _on_perm_create_allowed_tags_changed(self, event: checkbox_input.CheckboxInput.Changed) -> None:
        self._perm_create_allowed_tags = _Field(event.active, event.value)

    @textual.on(checkbox_input.CheckboxInput.Changed, "#permission-create-req-boundaries")
    def _on_perm_create_req_boundaries_changed(self, event: checkbox_input.CheckboxInput.Changed) -> None:
        self._perm_create_req_boundaries = _Field(event.active, event.value)

    @textual.on(textual.widgets.Checkbox.Changed, "#permission-read")
    def _on_perm_read_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self._perm_read = event.value

    @textual.on(textual.widgets.Checkbox.Changed, "#permission-update-name")
    def _on_perm_update_name_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self._perm_update_name = event.value

    @textual.on(textual.widgets.Checkbox.Changed, "#permission-delete")
    def _on_perm_delete_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self._perm_delete = event.value

    @textual.on(checkbox_input.CheckboxInput.Changed, "#permission-add-tag")
    def _on_perm_add_tag_changed(self, event: checkbox_input.CheckboxInput.Changed) -> None:
        self._perm_add_tag_list = _Field(event.active, event.value)

    @textual.on(checkbox_input.CheckboxInput.Changed, "#permission-del-tag")
    def _on_perm_del_tag_changed(self, event: checkbox_input.CheckboxInput.Changed) -> None:
        self._perm_del_tag_list = _Field(event.active, event.value)

    @textual.on(checkbox_input.CheckboxInput.Changed, "#permission-invite")
    def _on_perm_invite_changed(self, event: checkbox_input.CheckboxInput.Changed) -> None:
        self._perm_invite_list = _Field(event.active, event.value)

    def get_grant_data(self) -> tuple[dict, dict]:
        return (
            {
                "name": self._filter_name if self._filter_name_active else None,
                "tag_list": self._filter_tag_list.to_tag_list(inactive=None),
                "boundary_list": self._filter_boundary_list.to_boundary_list(inactive=None),
            },
            {
                "create": {
                    "allowed": self._perm_create_allowed,
                    "allowed_tag_list": self._perm_create_allowed_tags.to_tag_list(inactive=[]),
                    # Note that the inactive argument to to_boundary_list really does not
                    # matter because [] and None are semantically equivalent for this field.
                    "required_boundary_list": self._perm_create_req_boundaries.to_boundary_list(inactive=[]),
                },
                "read": self._perm_read,
                "update": {
                    "name": self._perm_update_name,
                },
                "delete": self._perm_delete,
                "add_tag_list": self._perm_add_tag_list.to_tag_list(inactive=[]),
                "del_tag_list": self._perm_del_tag_list.to_tag_list(inactive=[]),
                "invite_list": self._perm_invite_list.to_invite_list(),
            },
        )


class GrantEditScreen(textual.screen.Screen[dict | None]):
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
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "save", "Save"),
        ("escape", "cancel", "Cancel"),
        ("up", "app.focus_previous", ""),
        ("down", "app.focus_next", ""),
    ]
    grant_type: textual.reactive.Reactive[str] = textual.reactive.Reactive("")

    def __init__(self, auth: async_client.AsyncClient, grant: dict):
        super().__init__(id="grant-edit")
        self._auth = auth
        self.grant_type = grant["type"]
        self._filter = grant["filter"]
        self._permission = grant["permission"]

    async def watch_grant_type(self, value: str) -> None:
        fields = self.query_one("#dynamic-grant-fields")
        await fields.query("*").remove()
        match value:
            case "role":
                widget: textual.widget.Widget = RoleGrantEditWidget(self._auth, self._filter, self._permission)
            case "identity":
                widget = IdentityGrantEditWidget(self._auth, self._filter, self._permission)
            case _:
                return
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

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        fields = self.query_one("#dynamic-grant-fields")
        role_widgets = list(fields.query(RoleGrantEditWidget))
        identity_widgets = list(fields.query(IdentityGrantEditWidget))
        if role_widgets:
            filter_dict, permission = role_widgets[0].get_grant_data()
        elif identity_widgets:
            filter_dict, permission = identity_widgets[0].get_grant_data()
        else:
            return
        self.dismiss({"type": self.grant_type, "filter": filter_dict, "permission": permission})

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
        yield textual.widgets.Footer()
