from __future__ import annotations

import typing

import textual
import textual.app
import textual.containers
import textual.widgets

from . import base

GRANT_TYPES = ["identity", "tag", "role", "boundary", "tenant", "ssh"]


class GrantTypeScreen(base.ModalScreen[str | None]):
    DEFAULT_CSS = """
    GrantTypeScreen > VerticalGroup {
        width: auto;
    }
    #popup ListView {
        height: auto;
        width: auto;
        padding: 1 2;
    }
    #popup ListView ListItem{
        height: auto;
        width: auto;
    }
    """
    BINDINGS: typing.ClassVar = [
        ("escape", "cancel", "Cancel"),
        ("up", "app.focus_previous", ""),
        ("down", "app.focus_next", ""),
    ]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup(id="popup"):
            yield textual.widgets.ListView(
                *[
                    textual.widgets.ListItem(textual.widgets.Label(grant_type), id=grant_type)
                    for grant_type in GRANT_TYPES
                ]
            )

    def on_mount(self) -> None:
        self.query_one("#popup").border_title = "Add grant"

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_pressed(self, event: textual.widgets.ListView.Selected) -> None:
        self.dismiss(event.item.id)
