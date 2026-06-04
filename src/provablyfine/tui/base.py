from __future__ import annotations

import textual.app
import textual.screen
import textual.widget
import textual.worker
import provablyfine_client as pfc


class App(textual.app.App[None]):
    def _handle_exception(self, error: Exception) -> None:
        ui_error: pfc.exceptions.UI | None = None
        if isinstance(error, pfc.exceptions.UI):
            ui_error = error
        elif isinstance(error, textual.worker.WorkerFailed) and isinstance(error.error, pfc.exceptions.UI):
            ui_error = error.error
        if ui_error is not None:
            self.notify(str(ui_error), severity="error")
            return
        super()._handle_exception(error)


class Widget(textual.widget.Widget):
    @property
    def app(self) -> App:
        return super().app  # type: ignore


class Screen(textual.screen.Screen[None]):
    @property
    def app(self) -> App:
        return super().app  # type: ignore


class ModalScreen[T](textual.screen.ModalScreen[T]):
    @property
    def app(self) -> App:
        return super().app  # type: ignore
