import textual
import textual.app
import textual.widgets
import textual.containers
import textual_autocomplete

from ... import client
from ...client import schemas
from .. import auto_complete, checkbox_input
from . import base


class RoleGrantEditWidget(base.GrantEditWidget):
    DEFAULT_CSS = """
    RoleGrantEditWidget {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, grant: schemas.RoleGrant):
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
                placeholder="Type a role name",
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
                ("Update member list", "update.member_list", True if update is None else update.member_list),
                ("Update grant list", "update.grant_list", True if update is None else update.grant_list),
                ("Delete", "delete", p.delete),
                compact=True,
            )

    async def on_mount(self) -> None:
        roles = (await self._auth.list_roles()).roles
        candidates = [textual_autocomplete.DropdownItem(main=r.name) for r in roles]
        self.query_one("#filter-name", checkbox_input.CheckboxInput).set_candidates(candidates)

    def get_grant_data(self) -> schemas.RoleGrant:
        selected = set(self.query_one(textual.widgets.SelectionList).selected)
        update_dict = {
            "name": "update.name" in selected,
            "description": "update.description" in selected,
            "member_list": "update.member_list" in selected,
            "grant_list": "update.grant_list" in selected,
        }
        return schemas.RoleGrant(
            type="role",
            filter=schemas.RoleFilter(name=self._read_field("#filter-name").name_filter()),
            permission=schemas.RolePermission(
                create="create" in selected,
                read="read" in selected,
                update=schemas.RoleUpdatePermission(**update_dict),
                delete="delete" in selected,
            ),
        )
