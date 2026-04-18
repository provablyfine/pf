import textual
import textual.app
import textual.widgets
import textual.containers
import textual_autocomplete

from ... import client
from ...client import schemas
from .. import auto_complete, checkbox_input
from .base import _Field, _GrantEditWidget


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

    def __init__(self, auth: client.aio.Client, grant: schemas.IdentityGrant):
        super().__init__()
        self._auth = auth
        self._grant = grant

    def compose(self) -> textual.app.ComposeResult:
        f = self._grant.filter
        p = self._grant.permission
        create = p.create
        tag_list = _Field.from_tag_list(f.tag_list)
        boundary_list = _Field.from_boundary_list(f.boundary_list)
        create_tags = _Field.from_tag_list((create.allowed_tag_list or None) if create else None)
        create_bounds = _Field.from_boundary_list((create.required_boundary_list or None) if create else None)
        add_tag = _Field.from_tag_list(p.add_tag_list)
        del_tag = _Field.from_tag_list(p.del_tag_list)
        invite = _Field.from_invite_list(p.invite_list)
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            yield checkbox_input.CheckboxInput(
                "Name",
                active=f.name is not None,
                value=f.name or "",
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
            yield textual.widgets.Checkbox(
                "Create", value=create.allowed if create else False, id="permission-create", compact=True
            )
            with textual.containers.Container(
                id="permission-create-fields", disabled=not (create.allowed if create else False)
            ):
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
            yield textual.widgets.Checkbox("Read", value=p.read, id="permission-read", compact=True)
            yield textual.widgets.Checkbox(
                "Update", value=p.update.name if p.update else False, id="permission-update-name", compact=True
            )
            yield textual.widgets.Checkbox("Delete", value=p.delete, id="permission-delete", compact=True)
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
        identities = (await self._auth.list_identities()).identities
        identity_candidates = [textual_autocomplete.DropdownItem(main=i.name) for i in identities]
        self.query_one("#filter-name", checkbox_input.CheckboxInput).set_candidates(identity_candidates)

        tags_raw = (await self._auth.list_tags()).tags
        tags = [textual_autocomplete.DropdownItem(main=f"{t.name}={t.value}") for t in tags_raw]
        self.query_one("#filter-tagged-by", checkbox_input.CheckboxInput).set_candidates(tags)
        self.query_one("#permission-create-allowed-tags", checkbox_input.CheckboxInput).set_candidates(tags)
        self.query_one("#permission-add-tag", checkbox_input.CheckboxInput).set_candidates(tags)
        self.query_one("#permission-del-tag", checkbox_input.CheckboxInput).set_candidates(tags)

        boundaries_raw = (await self._auth.list_boundaries()).boundaries
        boundaries = [textual_autocomplete.DropdownItem(main=b.name) for b in boundaries_raw]
        self.query_one("#filter-bounded-by", checkbox_input.CheckboxInput).set_candidates(boundaries)
        self.query_one("#permission-create-req-boundaries", checkbox_input.CheckboxInput).set_candidates(boundaries)

        invite_methods = [textual_autocomplete.DropdownItem(main=m) for m in ("email", "manual")]
        self.query_one("#permission-invite", checkbox_input.CheckboxInput).set_candidates(invite_methods)

    @textual.on(textual.widgets.Checkbox.Changed, "#permission-create")
    def _on_perm_create_changed(self, event: textual.widgets.Checkbox.Changed) -> None:
        self.query_one("#permission-create-fields").disabled = not event.value

    def get_grant_data(self) -> schemas.IdentityGrant:
        create_perm = self.query_one("#permission-create", textual.widgets.Checkbox).value
        return schemas.IdentityGrant(
            type="identity",
            filter=schemas.TripletFilter(
                name=self._read_field("#filter-name").name_filter(),
                tag_list=self._read_field("#filter-tagged-by").tag_filter(),
                boundary_list=self._read_field("#filter-bounded-by").boundary_filter(),
            ),
            permission=schemas.IdentityPermission(
                create=schemas.IdentityCreatePermission(
                    allowed=create_perm,
                    allowed_tag_list=self._read_field("#permission-create-allowed-tags").tag_perm(),
                    required_boundary_list=self._read_field("#permission-create-req-boundaries").boundary_perm(),
                ),
                read=self.query_one("#permission-read", textual.widgets.Checkbox).value,
                update=schemas.IdentityUpdatePermission(
                    name=self.query_one("#permission-update-name", textual.widgets.Checkbox).value,
                ),
                delete=self.query_one("#permission-delete", textual.widgets.Checkbox).value,
                add_tag_list=self._read_field("#permission-add-tag").tag_perm(),
                del_tag_list=self._read_field("#permission-del-tag").tag_perm(),
                invite_list=self._read_field("#permission-invite").invite_perm(),
            ),
        )
