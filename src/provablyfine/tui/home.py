import collections.abc
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.widgets

from . import (
    audit_log_list,
    auth_list,
    base,
    bastion_list,
    boundary_list,
    header,
    identity_list,
    role_list,
    tag_list,
    tenant_list,
)

_RESOURCES: list[tuple[str, collections.abc.Callable[[pfc.AsyncSessionClient], base.Screen]]] = [
    (base.BREADCRUMB_TENANTS, tenant_list.TenantListScreen),
    (base.BREADCRUMB_IDENTITIES, identity_list.IdentityListScreen),
    (base.BREADCRUMB_BASTIONS, bastion_list.BastionListScreen),
    (base.BREADCRUMB_BOUNDARIES, boundary_list.BoundaryListScreen),
    (base.BREADCRUMB_TAGS, tag_list.TagListScreen),
    (base.BREADCRUMB_ROLES, role_list.RoleListScreen),
    (base.BREADCRUMB_AUTHS, auth_list.AuthListScreen),
    (base.BREADCRUMB_AUDIT_LOG, audit_log_list.AuditLogListScreen),
]


class HomeScreen(base.Screen):
    DEFAULT_CSS = """
    HomeScreen ListView {
        border: solid $primary;
        width: 30;
        height: auto;
        margin: 1 2;
    }
    """
    BINDINGS: typing.ClassVar = [
        ("enter", "select", "Select"),
        ("escape", "app.quit", "Quit"),
    ]

    def __init__(self, auth: pfc.AsyncSessionClient) -> None:
        super().__init__()
        self._auth = auth

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.widgets.ListView() as lv:
            lv.border_title = "Resources"
            for name, _ in _RESOURCES:
                yield textual.widgets.ListItem(textual.widgets.Label(name))
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    def action_select(self) -> None:
        lv = self.query_one(textual.widgets.ListView)
        index = lv.index
        if index is None:
            return
        _, make_screen = _RESOURCES[index]
        self.app.push_screen(make_screen(self._auth))

    def refresh_auth(self, auth: pfc.AsyncSessionClient) -> None:
        self._auth = auth

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self, event: textual.widgets.ListView.Selected) -> None:
        self.action_select()
