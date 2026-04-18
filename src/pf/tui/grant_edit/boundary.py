import textual
import textual.app
import textual.containers
import textual_autocomplete

from ... import client
from .. import auto_complete, checkbox_input
from .base import _GrantEditWidget, _resolve_update_perm


class BoundaryGrantEditWidget(_GrantEditWidget):
    DEFAULT_CSS = """
    BoundaryGrantEditWidget {
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
                placeholder="boundary name",
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
                ("Update ceiling list", "update.ceiling_list", _resolve_update_perm(update, "ceiling_list")),
                ("Update denied list", "update.denied_list", _resolve_update_perm(update, "denied_list")),
                ("Delete", "delete", p["delete"]),
                compact=True,
            )

    async def on_mount(self) -> None:
        boundaries_raw = (await self._auth.list_boundaries()).boundaries
        candidates = [textual_autocomplete.DropdownItem(main=b.name) for b in boundaries_raw]
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
                    "ceiling_list": "update.ceiling_list" in selected,
                    "denied_list": "update.denied_list" in selected,
                },
                "delete": "delete" in selected,
            },
        )
