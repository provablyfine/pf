import dataclasses

import textual
import textual.widget

from ... import client
from ...client import schemas
from .. import checkbox_input


@dataclasses.dataclass
class _Field:
    active: bool
    value: str

    def tag_filter(self) -> list[schemas.TagNameValue] | None:
        if not self.active:
            return None
        return [
            schemas.TagNameValue(name=k, value=v)
            for k, v in (s.split("=", 1) for s in self.value.split() if "=" in s)
        ]

    def tag_perm(self) -> list[schemas.TagNameValue]:
        if not self.active:
            return []
        return [
            schemas.TagNameValue(name=k, value=v)
            for k, v in (s.split("=", 1) for s in self.value.split() if "=" in s)
        ]

    def boundary_filter(self) -> list[str] | None:
        return self.value.split() if self.active else None

    def boundary_perm(self) -> list[str]:
        return self.value.split() if self.active else []

    def invite_perm(self) -> list[str]:
        return [s for s in self.value.split() if s in ("email", "manual")] if self.active else []

    def name_filter(self) -> str | None:
        name = self.value.strip()
        return name if (self.active and name) else None

    def tag_name_value_filter(self) -> schemas.TagNameValue | None:
        if not self.active:
            return None
        items = [s.split("=", 1) for s in self.value.split() if "=" in s]
        if not items:
            return None
        k, v = items[0]
        return schemas.TagNameValue(name=k, value=v)

    def int_filter(self) -> int | None:
        if not self.active:
            return None
        s = self.value.strip()
        return int(s) if s.isdigit() else None

    @classmethod
    def from_tag_list(cls, tag_list: list[schemas.TagNameValue] | None) -> "_Field":
        return cls(
            active=tag_list is not None,
            value=" ".join(f"{t.name}={t.value}" for t in (tag_list or [])),
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


def new_grant(grant_type: str) -> schemas.Grant:
    match grant_type:
        case "role":
            return schemas.RoleGrant(
                type="role",
                filter=schemas.RoleFilter(name=None),
                permission=schemas.RolePermission(
                    create=False,
                    read=False,
                    update=schemas.RoleUpdatePermission(
                        name=False, description=False, grant_list=False, member_list=False
                    ),
                    delete=False,
                ),
            )
        case "identity":
            return schemas.IdentityGrant(
                type="identity",
                filter=schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=schemas.IdentityPermission(
                    create=schemas.IdentityCreatePermission(
                        allowed=False, allowed_tag_list=[], required_boundary_list=None
                    ),
                    read=False,
                    update=schemas.IdentityUpdatePermission(name=False),
                    delete=False,
                    add_tag_list=None,
                    del_tag_list=None,
                    invite_list=None,
                ),
            )
        case "tag":
            return schemas.TagGrant(
                type="tag",
                filter=schemas.TagFilter(name_value=None),
                permission=schemas.TagPermission(create=False, read=False, delete=False),
            )
        case "boundary":
            return schemas.BoundaryGrant(
                type="boundary",
                filter=schemas.BoundaryFilter(name=None),
                permission=schemas.BoundaryPermission(
                    create=False,
                    read=False,
                    update=schemas.BoundaryUpdatePermission(
                        name=False, description=False, ceiling_list=False, denied_list=False
                    ),
                    delete=False,
                ),
            )
        case "tenant":
            return schemas.TenantGrant(
                type="tenant",
                filter=schemas.TenantFilter(id=None),
                permission=schemas.TenantPermission(
                    create=False,
                    read=False,
                    update=schemas.TenantUpdatePermission(display_name=False, is_enabled=False),
                    delete=False,
                ),
            )
        case "ssh-shell":
            return schemas.SSHShellGrant(
                type="ssh-shell",
                filter=schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=schemas.SSHShellPermission(
                    username_list=[],
                    permit_agent_forwarding=False,
                    permit_x11_forwarding=False,
                ),
            )
        case "ssh-port-forwarding":
            return schemas.SSHPortForwardingGrant(
                type="ssh-port-forwarding",
                filter=schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=schemas.SSHPortForwardingPermission(username_list=[]),
            )
        case "ssh-command":
            return schemas.SSHCommandGrant(
                type="ssh-command",
                filter=schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=schemas.SSHCommandPermission(username_list=[], command_list=[]),
            )
        case _:
            return schemas.InvalidGrant(type="invalid")


class _GrantEditWidget(textual.widget.Widget):
    def get_grant_data(self) -> schemas.Grant:
        raise NotImplementedError

    def _read_field(self, widget_id: str) -> _Field:
        w = self.query_one(widget_id, checkbox_input.CheckboxInput)
        return _Field(w.active, w.value)


class _SshBaseGrantEditWidget(_GrantEditWidget):
    def __init__(self, auth: client.aio.Client, grant: schemas.Grant):
        super().__init__()
        self._auth = auth
        self._grant = grant

    def _compose_filter(self):
        import textual.containers

        f = self._grant.filter
        tag_list = _Field.from_tag_list(f.tag_list)
        boundary_list = _Field.from_boundary_list(f.boundary_list)
        with textual.containers.VerticalGroup(classes="section"):
            yield textual.widgets.Label("Filters", classes="label")
            from .. import auto_complete

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

    async def _mount_filter_candidates(self) -> None:
        import textual_autocomplete

        identities = (await self._auth.list_identities()).identities
        identity_candidates = [textual_autocomplete.DropdownItem(main=i.name) for i in identities]
        self.query_one("#filter-name", checkbox_input.CheckboxInput).set_candidates(identity_candidates)

        tags_raw = (await self._auth.list_tags()).tags
        tags = [textual_autocomplete.DropdownItem(main=f"{t.name}={t.value}") for t in tags_raw]
        self.query_one("#filter-tagged-by", checkbox_input.CheckboxInput).set_candidates(tags)

        boundaries_raw = (await self._auth.list_boundaries()).boundaries
        boundaries = [textual_autocomplete.DropdownItem(main=b.name) for b in boundaries_raw]
        self.query_one("#filter-bounded-by", checkbox_input.CheckboxInput).set_candidates(boundaries)

    def _filter_data(self) -> schemas.TripletFilter:
        return schemas.TripletFilter(
            name=self._read_field("#filter-name").name_filter(),
            tag_list=self._read_field("#filter-tagged-by").tag_filter(),
            boundary_list=self._read_field("#filter-bounded-by").boundary_filter(),
        )
