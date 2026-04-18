import textual
import textual.app
import textual.widgets
import textual.containers
import textual_autocomplete

from ... import client
from ...client import schemas
from .. import auto_complete, checkbox_input
from . import base


class BoundaryGrantEditWidget(base.GrantEditWidget):
    DEFAULT_CSS = """
    BoundaryGrantEditWidget {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, grant: schemas.BoundaryGrant):
        super().__init__()
        self._auth = auth
        self._grant = grant

    def compose(self) -> textual.app.ComposeResult:
        f = self._grant.filter
        p = self._grant.permission
        update = p.update
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            yield checkbox_input.CheckboxInput(
                "Name",
                active=f.name is not None,
                value=f.name or "",
                placeholder="boundary name",
                id="filter-name",
                autocomplete=auto_complete.MonoAutoComplete,
            )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield textual.widgets.SelectionList(
                ("Create", "create", p.create),
                ("Read", "read", p.read),
                ("Update name", "update.name", True if update is None else update.name),
                ("Update description", "update.description", True if update is None else update.description),
                ("Update ceiling list", "update.ceiling_list", True if update is None else update.ceiling_list),
                ("Update denied list", "update.denied_list", True if update is None else update.denied_list),
                ("Delete", "delete", p.delete),
                compact=True,
            )

    async def on_mount(self) -> None:
        boundaries_raw = (await self._auth.list_boundaries()).boundaries
        candidates = [textual_autocomplete.DropdownItem(main=b.name) for b in boundaries_raw]
        self.query_one("#filter-name", checkbox_input.CheckboxInput).set_candidates(candidates)

    def get_grant_data(self) -> schemas.BoundaryGrant:
        selected = set(self.query_one(textual.widgets.SelectionList).selected)
        update_dict = {
            "name": "update.name" in selected,
            "description": "update.description" in selected,
            "ceiling_list": "update.ceiling_list" in selected,
            "denied_list": "update.denied_list" in selected,
        }
        return schemas.BoundaryGrant(
            type="boundary",
            filter=schemas.BoundaryFilter(name=self._read_field("#filter-name").name_filter()),
            permission=schemas.BoundaryPermission(
                create="create" in selected,
                read="read" in selected,
                update=schemas.BoundaryUpdatePermission(**update_dict),
                delete="delete" in selected,
            ),
        )
