import dataclasses

import textual
import textual.app
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


class NavPane(textual.widget.Widget):
    """Persistent, top-left, vertical navigation list. `base.Screen`
    injects one into every screen via `_extend_compose`, so individual
    screens never need to know it exists. A plain `ListView` is used so it
    needs no custom focus bindings: it's already part of Textual's default
    Tab/Shift+Tab chain. Group headings are `disabled=True` `ListItem`s —
    `ListView` already skips disabled items on up/down and never selects
    them, so no custom "non-selectable row" handling is needed.

    `dock: left` reserves its column against the *whole* screen regardless
    of other docked siblings (Textual doesn't stack simultaneous docks into
    a frame the way a browser's CSS would), which is why an unmargined
    `NavPane` would overlap `AppHeader`'s docked-top row. The top margin
    below clears it — it assumes the header is its normal single-row
    height, which doesn't hold while `AppHeader` is toggled to its tall
    (3-row) state."""

    DEFAULT_CSS = """
    NavPane {
        dock: left;
        width: 24;
        height: auto;
        margin: 0 0;
    }
    NavPane ListView {
        border: round $primary;
        height: auto;
        padding: 0 0;
    }
    NavPane ListItem.-heading Label {
        text-style: bold italic;
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
        self.watch(self.app, "whoami", self._set_subtitle)
        if self._active_id is None:
            return
        lv = self.query_one(textual.widgets.ListView)
        for index, item in enumerate(lv.children):
            if item.id == _item_id(self._active_id):
                lv.index = index
                break

    def _set_subtitle(self, whoami: str) -> None:
        self.query_one(textual.widgets.ListView).border_subtitle = whoami or None

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self, event: textual.widgets.ListView.Selected) -> None:
        item_id = event.item.id
        if item_id is None or not item_id.startswith("nav-"):
            return
        self.post_message(self.Activated(item_id.removeprefix("nav-")))
