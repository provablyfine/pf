import collections.abc
import typing

import textual
import textual.app
import textual.screen
import textual.widgets

from . import (
    async_client,
    auth_list,
    bastion_list,
    boundary_list,
    header,
    identity_list,
    role_list,
    tag_list,
    tenant_list,
)

_RESOURCES: list[tuple[str, collections.abc.Callable[[async_client.AsyncClient], textual.screen.Screen]]] = [
    ("Tenants", tenant_list.TenantListScreen),
    ("Identities", identity_list.IdentityListScreen),
    ("Bastions", bastion_list.BastionListScreen),
    ("Boundaries", boundary_list.BoundaryListScreen),
    ("Tags", tag_list.TagListScreen),
    ("Roles", role_list.RoleListScreen),
    ("Auths", auth_list.AuthListScreen),
]


class HomeScreen(textual.screen.Screen[None]):
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

    def __init__(self, auth: async_client.AsyncClient) -> None:
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

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self, event: textual.widgets.ListView.Selected) -> None:
        self.action_select()
