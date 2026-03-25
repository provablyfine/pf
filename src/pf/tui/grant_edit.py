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

from . import async_client, auto_complete, checkbox_input, header


@dataclasses.dataclass
class _Field:
    active: bool
    value: str

    def tag_filter(self) -> list[dict] | None:
        if not self.active:
            return None
        return [{"name": k, "value": v} for k, v in (s.split("=", 1) for s in self.value.split() if "=" in s)]

    def tag_perm(self) -> list[dict]:
        if not self.active:
            return []
        return [{"name": k, "value": v} for k, v in (s.split("=", 1) for s in self.value.split() if "=" in s)]

    def boundary_filter(self) -> list[str] | None:
        return self.value.split() if self.active else None

    def boundary_perm(self) -> list[str]:
        return self.value.split() if self.active else []

    def invite_perm(self) -> list[str]:
        return [s for s in self.value.split() if s in ("email", "manual")] if self.active else []

    def name_filter(self) -> str | None:
        name = self.value.strip()
        return name if (self.active and name) else None

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


def _resolve_update_perm(update: dict | None, field: str) -> bool:
    """Return the value of an update permission field.

    When update is None it means all update permissions are granted (wildcard).
    """
    if update is None:
        return True
    return update[field]


def new_grant(grant_type: str) -> dict:
    match grant_type:
        case "role":
            return {
                "type": "role",
                "filter": {"name": None},
                "permission": {
                    "create": False,
                    "read": False,
                    "update": {"name": False, "description": False, "grant_list": False, "member_list": False},
                    "delete": False,
                },
            }
        case "identity":
            return {
                "type": "identity",
                "filter": {"name": None, "tag_list": None, "boundary_list": None},
                "permission": {
                    "create": {"allowed": False, "allowed_tag_list": [], "required_boundary_list": None},
                    "read": False,
                    "update": {"name": False},
                    "delete": False,
                    "add_tag_list": None,
                    "del_tag_list": None,
                    "invite_list": None,
                },
            }
        case _:
            return {"type": grant_type, "filter": {}, "permission": {}}


class _GrantEditWidget(textual.widget.Widget):
    def get_grant_data(self) -> tuple[dict, dict]:
        raise NotImplementedError

    def _read_field(self, widget_id: str) -> _Field:
        w = self.query_one(widget_id, checkbox_input.CheckboxInput)
        return _Field(w.active, w.value)


class RoleGrantEditWidget(_GrantEditWidget):
    DEFAULT_CSS = """
    RoleGrantEditWidget {
        height: auto;
    }
    """

    def __init__(self, auth: async_client.AsyncClient, filter: dict, permission: dict):
        super().__init__()
        self._auth = auth
        self._initial_filter = filter
        self._initial_permission = permission

    def compose(self) -> textual.app.ComposeResult:
        f = self._initial_filter
        p = self._initial_permission
        update = p["update"]
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            yield checkbox_input.CheckboxInput(
                "Name",
                active=f["name"] is not None,
                value=f["name"] or "",
                placeholder="Type a role name",
                id="filter-name",
                autocomplete=auto_complete.MonoAutoComplete,
            )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.SelectionList(
                ("Create", "create", p["create"]),
                ("Read", "read", p["read"]),
                ("Update name", "update.name", _resolve_update_perm(update, "name")),
                ("Update description", "update.description", _resolve_update_perm(update, "description")),
                ("Update member list", "update.member_list", _resolve_update_perm(update, "member_list")),
                ("Update grant list", "update.grant_list", _resolve_update_perm(update, "grant_list")),
                ("Delete", "delete", p["delete"]),
                compact=True,
            )

    async def on_mount(self) -> None:
        roles = await self._auth.list_roles()
        candidates = [textual_autocomplete.DropdownItem(main=r["name"]) for r in roles]
        self.query_one("#filter-name", checkbox_input.CheckboxInput).set_candidates(candidates)

    def get_grant_data(self) -> tuple[dict, dict]:
        selected = set(self.query_one(textual.widgets.SelectionList).selected)
        return (
            {"name": self._read_field("#filter-name").name_filter()},
            {
                "create": "create" in selected,
                "read": "read" in selected,
                "update": {
                    "name": "update.name" in selected,
                    "description": "update.description" in selected,
                    "member_list": "update.member_list" in selected,
                    "grant_list": "update.grant_list" in selected,
                },
                "delete": "delete" in selected,
            },
        )


class IdentityGrantEditWidget(_GrantEditWidget):
    DEFAULT_CSS = """
    IdentityGrantEditWidget {
        height: auto;
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
        self._initial_filter = filter
        self._initial_permission = permission

    def compose(self) -> textual.app.ComposeResult:
        f = self._initial_filter
        p = self._initial_permission
        create = p["create"]
        tag_list = _Field.from_tag_list(f.get("tag_list"))
        boundary_list = _Field.from_boundary_list(f.get("boundary_list"))
        create_tags = _Field.from_tag_list(create.get("allowed_tag_list") or None)
        create_bounds = _Field.from_boundary_list(create.get("required_boundary_list"))
        add_tag = _Field.from_tag_list(p.get("add_tag_list"))
        del_tag = _Field.from_tag_list(p.get("del_tag_list"))
        invite = _Field.from_invite_list(p.get("invite_list"))
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            yield checkbox_input.CheckboxInput(
                "Name",
                active=f["name"] is not None,
                value=f["name"] or "",
                placeholder="Type an identity name",
                id="filter-name",
                autocomplete=auto_complete.MonoAutoComplete,
            )
            yield checkbox_input.CheckboxInput(
                "Tagged by",
                active=tag_list.active,
                value=tag_list.value,
                placeholder="Type a tag name=value",
                id="filter-tagged-by",
            )
            yield checkbox_input.CheckboxInput(
                "Bounded by",
                active=boundary_list.active,
                value=boundary_list.value,
                placeholder="Type a boundary name",
                id="filter-bounded-by",
            )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.Checkbox("Create", value=create["allowed"], id="permission-create", compact=True)
            with textual.containers.Container(id="permission-create-fields", disabled=not create["allowed"]):
                yield checkbox_input.CheckboxInput(
                    "Create allowed tags",
                    active=create_tags.active,
                    value=create_tags.value,
                    placeholder="Type a tag name=value",
                    id="permission-create-allowed-tags",
                )
                yield checkbox_input.CheckboxInput(
                    "Create required boundaries",
                    active=create_bounds.active,
                    value=create_bounds.value,
                    placeholder="Type a boundary name",
                    id="permission-create-req-boundaries",
                )
            yield textual.widgets.Checkbox("Read", value=p["read"], id="permission-read", compact=True)
            yield textual.widgets.Checkbox(
                "Update", value=_resolve_update_perm(p["update"], "name"), id="permission-update-name", compact=True
            )
            yield textual.widgets.Checkbox("Delete", value=p["delete"], id="permission-delete", compact=True)
            yield checkbox_input.CheckboxInput(
                "Add tag",
                active=add_tag.active,
                value=add_tag.value,
                placeholder="Type a tag name=value",
                id="permission-add-tag",
            )
            yield checkbox_input.CheckboxInput(
                "Del tag",
                active=del_tag.active,
                value=del_tag.value,
                placeholder="Type a tag name=value",
                id="permission-del-tag",
            )
            yield checkbox_input.CheckboxInput(
                "Invite",
                active=invite.active,
                value=invite.value,
                placeholder="email manual",
                id="permission-invite",
            )

    async def on_mount(self) -> None:
        identities = await self._auth.list_identities()
        identity_candidates = [textual_autocomplete.DropdownItem(main=i["name"]) for i in identities]
        self.query_one("#filter-name", checkbox_input.CheckboxInput).set_candidates(identity_candidates)

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

    @textual.on(textual.widgets.Checkbox.Changed, "#permission-create")
    def _on_perm_create_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self.query_one("#permission-create-fields").disabled = not event.value

    def get_grant_data(self) -> tuple[dict, dict]:
        return (
            {
                "name": self._read_field("#filter-name").name_filter(),
                "tag_list": self._read_field("#filter-tagged-by").tag_filter(),
                "boundary_list": self._read_field("#filter-bounded-by").boundary_filter(),
            },
            {
                "create": {
                    "allowed": self.query_one("#permission-create", textual.widgets.Checkbox).value,
                    "allowed_tag_list": self._read_field("#permission-create-allowed-tags").tag_perm(),
                    "required_boundary_list": self._read_field("#permission-create-req-boundaries").boundary_perm(),
                },
                "read": self.query_one("#permission-read", textual.widgets.Checkbox).value,
                "update": {
                    "name": self.query_one("#permission-update-name", textual.widgets.Checkbox).value,
                },
                "delete": self.query_one("#permission-delete", textual.widgets.Checkbox).value,
                "add_tag_list": self._read_field("#permission-add-tag").tag_perm(),
                "del_tag_list": self._read_field("#permission-del-tag").tag_perm(),
                "invite_list": self._read_field("#permission-invite").invite_perm(),
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
        self.sub_title = f"Edit {value} grant"
        fields = self.query_one("#dynamic-grant-fields")
        await fields.query("*").remove()
        match value:
            case "role":
                widget: _GrantEditWidget = RoleGrantEditWidget(self._auth, self._filter, self._permission)
            case "identity":
                widget = IdentityGrantEditWidget(self._auth, self._filter, self._permission)
            case _:
                return
        await fields.mount(widget)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_save(self) -> None:
        widgets = list(self.query_one("#dynamic-grant-fields").query(_GrantEditWidget))
        if not widgets:
            return
        filter_dict, permission = widgets[0].get_grant_data()
        self.dismiss({"type": self.grant_type, "filter": filter_dict, "permission": permission})

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.VerticalGroup(classes="sections"):
            yield textual.containers.Container(id="dynamic-grant-fields")
        yield textual.widgets.Footer()
