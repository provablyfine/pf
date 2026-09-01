import dataclasses

import textual
import textual.app
import textual.containers
import textual.message
import textual.widget
import textual.widgets


@dataclasses.dataclass(frozen=True)
class _Section:
    id: str
    label: str


@dataclasses.dataclass(frozen=True)
class _Group:
    heading: str
    sections: list[_Section]


# Single source of truth for section id, label, grouping, and display order.
# Kept free of any dependency on `base.py` or the screen modules: `base.Screen`
# injects this widget into every screen via `_extend_compose` (the same
# mechanism Textual's own `Screen` uses for `ToastRack`/`Tooltip`), so a
# dependency the other way (`base` -> `nav_pane`) would cycle back here if
# this module depended on `base` too.
NAV_GROUPS: list[_Group] = [
    _Group(
        "Access Control",
        [
            _Section("identities", "Identities"),
            _Section("tags", "Tags"),
            _Section("roles", "Roles"),
            _Section("boundaries", "Boundaries"),
        ],
    ),
    _Group(
        "Admin",
        [
            _Section("auths", "Authentication"),
            _Section("bastions", "Bastions"),
            _Section("tenants", "Tenants"),
        ],
    ),
    _Group("Audit", [_Section("audit_log", "Action log")]),
]

NAV_ITEMS: list[tuple[str, str]] = [(section.id, section.label) for group in NAV_GROUPS for section in group.sections]


def _item_id(section_id: str) -> str:
    return f"nav-{section_id}"


class NavColumn(textual.widget.Widget):
    """Docked left column holding `NavPane` (the navigation list) followed by
    `SessionPane` (the inert tenant/role/identity panel). Only this outer
    widget docks — Textual places every docked widget from its container's
    own edge independently (it doesn't stack same-edge docks into a frame the
    way a browser's CSS would), so two separately-docked children here would
    both start at the top and overlap. `NavPane`/`SessionPane` instead rely on
    the default vertical layout to stack normally within this column.

    `dock: left` reserves this column against the *whole* screen regardless
    of other docked siblings, which is why `NavColumn` needs no top margin of
    its own: `AppHeader` always renders at `height: 0` (invisible, reserving
    no rows), so there is nothing for this column to clear."""

    DEFAULT_CSS = """
    NavColumn {
        dock: left;
        width: 24;
        height: auto;
    }
    """

    def __init__(self, active_id: str | None) -> None:
        super().__init__()
        self._active_id = active_id

    def compose(self) -> textual.app.ComposeResult:
        yield NavPane(active_id=self._active_id)
        yield SessionPane()


class NavPane(textual.widget.Widget):
    """Persistent navigation list, the top child of `NavColumn`. A plain
    `ListView` is used so it needs no custom focus bindings: it's already
    part of Textual's default Tab/Shift+Tab chain. Group headings are
    `disabled=True` `ListItem`s — `ListView` already skips disabled items on
    up/down and never selects them, so no custom "non-selectable row"
    handling is needed."""

    DEFAULT_CSS = """
    NavPane {
        width: 100%;
        height: auto;
    }
    NavPane ListView {
        background: transparent;
        border: round $primary;
        height: auto;
        padding: 0 0;
    }
    NavPane ListItem.-heading Label {
        color: $text-muted;
    }
    NavPane ListItem .-marker {
        dock: left;
        width: 2;
        text-align: left;
    }
    NavPane ListItem.-active .-label {
        text-style: bold;
    }
    """

    class Activated(textual.message.Message):
        def __init__(self, section_id: str) -> None:
            super().__init__()
            self.section_id = section_id

    @property
    def app(self) -> textual.app.App[None]:
        return super().app  # type: ignore

    def __init__(self, active_id: str | None) -> None:
        super().__init__()
        self._active_id = active_id

    def compose(self) -> textual.app.ComposeResult:
        with textual.widgets.ListView() as lv:
            lv.border_title = "Provably Fine"
            for group in NAV_GROUPS:
                yield textual.widgets.ListItem(textual.widgets.Label(group.heading), classes="-heading", disabled=True)
                for section in group.sections:
                    is_active = section.id == self._active_id
                    item = textual.widgets.ListItem(
                        textual.widgets.Label("*" if is_active else "", classes="-marker"),
                        textual.widgets.Label(section.label, classes="-label"),
                        id=_item_id(section.id),
                    )
                    if is_active:
                        item.add_class("-active")
                    yield item

    def on_mount(self) -> None:
        if self._active_id is None:
            return
        lv = self.query_one(textual.widgets.ListView)
        for index, item in enumerate(lv.children):
            if item.id == _item_id(self._active_id):
                lv.index = index
                break

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self, event: textual.widgets.ListView.Selected) -> None:
        item_id = event.item.id
        if item_id is None or not item_id.startswith("nav-"):
            return
        self.post_message(self.Activated(item_id.removeprefix("nav-")))


class SessionPane(textual.widget.Widget):
    """Inert panel below `NavPane`, the bottom child of `NavColumn`, showing
    the current tenant, role, and identity. Deliberately *not* a
    `ListView`/focusable control: nothing here can be selected today, and even
    once tenant/role switching exists it's planned as a global keybinding
    rather than a navigable row, so this stays a plain, inert container."""

    DEFAULT_CSS = """
    SessionPane {
        width: 100%;
        height: auto;
    }
    SessionPane > Vertical {
        border: round $primary;
        height: auto;
    }
    SessionPane Static {
        color: $text-muted;
        width: 100%;
    }
    """

    can_focus = False

    @property
    def app(self) -> textual.app.App[None]:
        return super().app  # type: ignore

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.Vertical() as v:
            v.border_title = "Session"
            yield textual.widgets.Static(id="session-tenant")
            yield textual.widgets.Static(id="session-role")
            yield textual.widgets.Static(id="session-identity")

    def on_mount(self) -> None:
        self.watch(self.app, "tenant_name", self._set_tenant)
        self.watch(self.app, "role", self._set_role)
        self.watch(self.app, "identity_name", self._set_identity)

    def _set_tenant(self, tenant_name: str) -> None:
        text = f"Tenant: {tenant_name}" if tenant_name else ""
        self.query_one("#session-tenant", textual.widgets.Static).update(text)

    def _set_role(self, role: str) -> None:
        self.query_one("#session-role", textual.widgets.Static).update(f"Role: {role}" if role else "")

    def _set_identity(self, identity_name: str) -> None:
        self.query_one("#session-identity", textual.widgets.Static).update(identity_name)
