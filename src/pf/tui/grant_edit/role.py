import textual
import textual.app
import textual.containers
import textual_autocomplete

from ... import client
from .. import auto_complete, checkbox_input
from .base import _GrantEditWidget, _resolve_update_perm


class RoleGrantEditWidget(_GrantEditWidget):
    DEFAULT_CSS = """
    RoleGrantEditWidget {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, filter: dict, permission: dict):
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
        roles = (await self._auth.list_roles()).roles
        candidates = [textual_autocomplete.DropdownItem(main=r.name) for r in roles]
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
