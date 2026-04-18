import textual
import textual.app
import textual.containers
import textual.widgets
import textual_autocomplete

from ... import client
from ...client import schemas
from .. import auto_complete, checkbox_input
from . import base


class PermissionSelectionList(textual.widgets.SelectionList[str]):
    pass


class TagGrantEditWidget(base.GrantEditWidget):
    DEFAULT_CSS = """
    TagGrantEditWidget {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, grant: schemas.TagGrant):
        super().__init__()
        self._auth = auth
        self._grant = grant

    def compose(self) -> textual.app.ComposeResult:
        f = self._grant.filter
        p = self._grant.permission
        nv = f.name_value
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            yield checkbox_input.CheckboxInput(
                "Tag",
                active=nv is not None,
                value=f"{nv.name}={nv.value}" if nv is not None else "",
                placeholder="name=value",
                id="filter-name-value",
                autocomplete=auto_complete.MonoAutoComplete,
            )
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Permissions", classes="label")
            yield PermissionSelectionList(
                ("Create", "create", p.create),
                ("Read", "read", p.read),
                ("Delete", "delete", p.delete),
                compact=True,
            )

    async def on_mount(self) -> None:
        tags_raw = (await self._auth.list_tags()).tags
        candidates = [textual_autocomplete.DropdownItem(main=f"{t.name}={t.value}") for t in tags_raw]
        self.query_one("#filter-name-value", checkbox_input.CheckboxInput).set_candidates(candidates)

    def get_grant_data(self) -> schemas.TagGrant:
        selected = set(self.query_one(PermissionSelectionList).selected)
        return schemas.TagGrant(
            type="tag",
            filter=schemas.TagFilter(name_value=self._read_field("#filter-name-value").tag_name_value_filter()),
            permission=schemas.TagPermission(
                create="create" in selected,
                read="read" in selected,
                delete="delete" in selected,
            ),
        )
