import textual
import textual.app
import textual.containers
import textual.widgets
import textual_autocomplete

from ... import client
from .. import auto_complete, checkbox_input
from . import base


class PermissionSelectionList(textual.widgets.SelectionList[str]):
    pass


class TenantGrantEditWidget(base.GrantEditWidget):
    DEFAULT_CSS = """
    TenantGrantEditWidget {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, grant: client.schemas.TenantGrant):
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
                "ID",
                active=f.id is not None,
                value=str(f.id) if f.id is not None else "",
                placeholder="tenant id",
                id="filter-id",
                autocomplete=auto_complete.MonoAutoComplete,
            )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield PermissionSelectionList(
                ("Create", "create", p.create),
                ("Read", "read", p.read),
                ("Update display name", "update.display_name", True if update is None else update.display_name),
                ("Update is enabled", "update.is_enabled", True if update is None else update.is_enabled),
                ("Delete", "delete", p.delete),
                compact=True,
            )

    async def on_mount(self) -> None:
        tenants_raw = (await self._auth.list_tenants()).tenants
        candidates = [textual_autocomplete.DropdownItem(main=str(t.id)) for t in tenants_raw]
        self.query_one("#filter-id", checkbox_input.CheckboxInput).set_candidates(candidates)

    def get_grant_data(self) -> client.schemas.TenantGrant:
        selected = self.query_one(PermissionSelectionList).selected
        update_dict = {
            "display_name": "update.display_name" in selected,
            "is_enabled": "update.is_enabled" in selected,
        }
        return client.schemas.TenantGrant(
            type="tenant",
            filter=client.schemas.TenantFilter(id=self._read_field("#filter-id").int_filter()),
            permission=client.schemas.TenantPermission(
                create="create" in selected,
                read="read" in selected,
                update=client.schemas.TenantUpdatePermission(**update_dict),
                delete="delete" in selected,
            ),
        )
