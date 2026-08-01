from __future__ import annotations

import dataclasses
import typing

import provablyfine_client as pfc
import textual
import textual.containers
import textual.widget
import textual.widgets
import textual_autocomplete

from .. import auto_complete, checkbox_input


class _TripletFilterGrant(typing.Protocol):
    filter: pfc.schemas.TripletFilter


@dataclasses.dataclass
class Field:
    active: bool
    value: str

    def tag_filter(self) -> list[pfc.schemas.TagNameValue] | None:
        if not self.active:
            return None
        return [
            pfc.schemas.TagNameValue(name=k, value=v)
            for k, v in (s.split("=", 1) for s in self.value.split() if "=" in s)
        ]

    def tag_perm(self) -> list[pfc.schemas.TagNameValue]:
        if not self.active:
            return []
        return [
            pfc.schemas.TagNameValue(name=k, value=v)
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

    def tag_name_value_filter(self) -> pfc.schemas.TagNameValue | None:
        if not self.active:
            return None
        items = [s.split("=", 1) for s in self.value.split() if "=" in s]
        if not items:
            return None
        k, v = items[0]
        return pfc.schemas.TagNameValue(name=k, value=v)

    def int_filter(self) -> int | None:
        if not self.active:
            return None
        s = self.value.strip()
        return int(s) if s.isdigit() else None

    @classmethod
    def from_tag_list(cls, tag_list: list[pfc.schemas.TagNameValue] | None) -> Field:
        return cls(
            active=tag_list is not None,
            value=" ".join(f"{t.name}={t.value}" for t in (tag_list or [])),
        )

    @classmethod
    def from_boundary_list(cls, boundary_list: list[str] | None) -> Field:
        return cls(
            active=boundary_list is not None,
            value=" ".join(boundary_list or []),
        )

    @classmethod
    def from_invite_list(cls, invite_list: list[str] | None) -> Field:
        return cls(
            active=invite_list is not None,
            value=" ".join(invite_list or []),
        )


def new_grant(grant_type: str) -> pfc.schemas.Grant:
    match grant_type:
        case "role":
            return pfc.schemas.RoleGrant(
                type="role",
                filter=pfc.schemas.RoleFilter(name=None),
                permission=pfc.schemas.RolePermission(
                    create=False,
                    read=False,
                    update=pfc.schemas.RoleUpdatePermission(
                        name=False, description=False, grant_list=False, member_list=False
                    ),
                    delete=False,
                ),
            )
        case "identity":
            return pfc.schemas.IdentityGrant(
                type="identity",
                filter=pfc.schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=pfc.schemas.IdentityPermission(
                    create=pfc.schemas.IdentityCreatePermission(
                        allowed=False, allowed_tag_list=[], required_boundary_list=None
                    ),
                    read=False,
                    update=pfc.schemas.IdentityUpdatePermission(name=False),
                    delete=False,
                    add_tag_list=None,
                    del_tag_list=None,
                    invite_list=None,
                ),
            )
        case "tag":
            return pfc.schemas.TagGrant(
                type="tag",
                filter=pfc.schemas.TagFilter(name_value=None),
                permission=pfc.schemas.TagPermission(create=False, read=False, delete=False),
            )
        case "boundary":
            return pfc.schemas.BoundaryGrant(
                type="boundary",
                filter=pfc.schemas.BoundaryFilter(name=None),
                permission=pfc.schemas.BoundaryPermission(
                    create=False,
                    read=False,
                    update=pfc.schemas.BoundaryUpdatePermission(
                        name=False, description=False, ceiling_list=False, denied_list=False
                    ),
                    delete=False,
                ),
            )
        case "tenant":
            return pfc.schemas.TenantGrant(
                type="tenant",
                filter=pfc.schemas.TenantFilter(id=None),
                permission=pfc.schemas.TenantPermission(
                    create=False,
                    read=False,
                    update=pfc.schemas.TenantUpdatePermission(display_name=False, is_enabled=False),
                    delete=False,
                ),
            )
        case "ssh-shell":
            return pfc.schemas.SSHShellGrant(
                type="ssh-shell",
                filter=pfc.schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=pfc.schemas.SSHShellPermission(
                    username_list=[],
                    permit_agent_forwarding=False,
                    permit_x11_forwarding=False,
                ),
            )
        case "ssh-port-forwarding":
            return pfc.schemas.SSHPortForwardingGrant(
                type="ssh-port-forwarding",
                filter=pfc.schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=pfc.schemas.SSHPortForwardingPermission(username_list=[]),
            )
        case "ssh-command":
            return pfc.schemas.SSHCommandGrant(
                type="ssh-command",
                filter=pfc.schemas.TripletFilter(name=None, tag_list=None, boundary_list=None),
                permission=pfc.schemas.SSHCommandPermission(username_list=[], command_list=[]),
            )
        case _:
            return pfc.schemas.InvalidGrant(type="invalid")


class GrantEditWidget(textual.widget.Widget):
    def get_grant_data(self) -> pfc.schemas.Grant:
        raise NotImplementedError

    def _read_field(self, widget_id: str) -> Field:
        w = self.query_one(widget_id, checkbox_input.CheckboxInput)
        return Field(w.active, w.value)


class TripletFilterGrantEditWidget[T: _TripletFilterGrant](GrantEditWidget):
    def __init__(self, auth: pfc.AsyncSessionClient, grant: T):
        super().__init__()
        self._auth = auth
        self._grant = grant

    def _compose_filter(self):
        f = self._grant.filter
        tag_list = Field.from_tag_list(f.tag_list)
        boundary_list = Field.from_boundary_list(f.boundary_list)
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

    async def _mount_filter_candidates(self) -> None:
        identities = (await self._auth.list_identities()).identities
        identity_candidates = [textual_autocomplete.DropdownItem(main=i.name) for i in identities]
        self.query_one("#filter-name", checkbox_input.CheckboxInput).set_candidates(identity_candidates)

        tags_raw = (await self._auth.list_tags()).tags
        tags = [textual_autocomplete.DropdownItem(main=f"{t.name}={t.value}") for t in tags_raw]
        self.query_one("#filter-tagged-by", checkbox_input.CheckboxInput).set_candidates(tags)

        boundaries_raw = (await self._auth.list_boundaries()).boundaries
        boundaries = [textual_autocomplete.DropdownItem(main=b.name) for b in boundaries_raw]
        self.query_one("#filter-bounded-by", checkbox_input.CheckboxInput).set_candidates(boundaries)

    def _filter_data(self) -> pfc.schemas.TripletFilter:
        return pfc.schemas.TripletFilter(
            name=self._read_field("#filter-name").name_filter(),
            tag_list=self._read_field("#filter-tagged-by").tag_filter(),
            boundary_list=self._read_field("#filter-bounded-by").boundary_filter(),
        )
