import collections.abc
import dataclasses

import provablyfine_client as pfc

from . import (
    audit_log_list,
    auth_list,
    base,
    bastion_list,
    boundary_list,
    identity_list,
    nav_pane,
    role_list,
    tag_list,
    tenant_list,
)

_FACTORIES: dict[str, collections.abc.Callable[[pfc.AsyncSessionClient], base.Screen]] = {
    "tenants": tenant_list.TenantListScreen,
    "identities": identity_list.IdentityListScreen,
    "bastions": bastion_list.BastionListScreen,
    "boundaries": boundary_list.BoundaryListScreen,
    "tags": tag_list.TagListScreen,
    "roles": role_list.RoleListScreen,
    "auths": auth_list.AuthListScreen,
    "audit_log": audit_log_list.AuditLogListScreen,
}


@dataclasses.dataclass(frozen=True)
class Section:
    id: str
    label: str
    factory: collections.abc.Callable[[pfc.AsyncSessionClient], base.Screen]


SECTIONS: list[Section] = [
    Section(id=section_id, label=label, factory=_FACTORIES[section_id]) for section_id, label in nav_pane.NAV_ITEMS
]


def factory_for(section_id: str) -> collections.abc.Callable[[pfc.AsyncSessionClient], base.Screen]:
    return _FACTORIES[section_id]
