from __future__ import annotations

import typing

import textual.widget
import textual.screen


if typing.TYPE_CHECKING:
    from . import app

class Widget(textual.widget.Widget):
    @property
    def app(self) -> app.TuiAppBase:
        return super().app # type: ignore

class Screen(textual.screen.Screen[None]):
    @property
    def app(self) -> app.TuiAppBase:
        return super().app # type: ignore
