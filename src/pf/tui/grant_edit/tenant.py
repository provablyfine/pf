import textual
import textual.app
import textual.containers
import textual_autocomplete

from ... import client
from .. import auto_complete, checkbox_input
from .base import _GrantEditWidget, _resolve_update_perm


class TenantGrantEditWidget(_GrantEditWidget):
    DEFAULT_CSS = """
    TenantGrantEditWidget {
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
                "ID",
                active=f["id"] is not None,
                value=str(f["id"]) if f["id"] is not None else "",
                placeholder="tenant id",
                id="filter-id",
                autocomplete=auto_complete.MonoAutoComplete,
            )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.SelectionList(
                ("Create", "create", p["create"]),
                ("Read", "read", p["read"]),
                ("Update display name", "update.display_name", _resolve_update_perm(update, "display_name")),
                ("Update is enabled", "update.is_enabled", _resolve_update_perm(update, "is_enabled")),
                ("Delete", "delete", p["delete"]),
                compact=True,
            )

    async def on_mount(self) -> None:
        tenants_raw = (await self._auth.list_tenants()).tenants
        candidates = [textual_autocomplete.DropdownItem(main=str(t.id)) for t in tenants_raw]
        self.query_one("#filter-id", checkbox_input.CheckboxInput).set_candidates(candidates)

    def get_grant_data(self) -> tuple[dict, dict]:
        selected = set(self.query_one(textual.widgets.SelectionList).selected)
        return (
            {"id": self._read_field("#filter-id").int_filter()},
            {
                "create": "create" in selected,
                "read": "read" in selected,
                "update": {
                    "display_name": "update.display_name" in selected,
                    "is_enabled": "update.is_enabled" in selected,
                },
                "delete": "delete" in selected,
            },
        )
