from __future__ import annotations

import provablyfine_client as pfc
import textual.app
import textual.await_complete
import textual.containers
import textual.css.query
import textual.events
import textual.reactive
import textual.screen
import textual.widget
import textual.widgets
import textual.worker

from . import nav_pane


class App(textual.app.App[None]):
    whoami: textual.reactive.Reactive[str] = textual.reactive.Reactive("")
    identity_name: textual.reactive.Reactive[str] = textual.reactive.Reactive("")
    role: textual.reactive.Reactive[str] = textual.reactive.Reactive("")
    tenant_name: textual.reactive.Reactive[str] = textual.reactive.Reactive("")
    current_section_id: str | None = None
    """Set by `TuiApp.switch_to_section`; read by `Screen._extend_compose`
    to decide whether (and with what active item) to inject a `NavColumn`.
    Stays `None` for `SetupApp` screens (login/setup, before any section
    exists), so they never get one."""

    def pop_screen(self) -> textual.await_complete.AwaitComplete:
        # `screen_stack[0]` is Textual's own implicit default screen,
        # invisible and empty. Every screen in this app binds `escape` to
        # `app.pop_screen` uniformly; popping past the app's own root screen
        # (depth 2) would leave that empty default screen on top with no way
        # back. `escape` should instead step "up" into the section root's own
        # `NavPane` at that point, rather than pop past it — `ctrl+q`
        # (Textual's default) is what quits.
        if len(self.screen_stack) <= 2:
            self._focus_nav_pane()
            return textual.await_complete.AwaitComplete.nothing()
        return super().pop_screen()

    def _focus_nav_pane(self) -> None:
        try:
            pane = self.screen.query_one(nav_pane.NavPane)
        except textual.css.query.NoMatches:
            return
        pane.query_one(textual.widgets.ListView).focus()

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
    # `DataTable`'s header row defaults to `background: $panel` — the exact
    # same token `AppHeader` uses — so the two blend together with nothing
    # to mark where the header ends and the screen's own content begins.
    DEFAULT_CSS = """
    Screen DataTable > .datatable--header {
        background: $boost;
    }
    Screen > .-content-frame {
        border: round $primary;
        height: 1fr;
    }
    """

    @property
    def app(self) -> App:
        return super().app  # type: ignore

    def set_breadcrumb(self, *parts: str) -> None:
        self.sub_title = format_breadcrumb(*parts)

    def _extend_compose(self, widgets: list[textual.widget.Widget]) -> None:
        super()._extend_compose(widgets)
        section_id = self.app.current_section_id
        if section_id is None:
            return
        label = next((label for id_, label in nav_pane.NAV_ITEMS if id_ == section_id), None)
        # Every screen in this app composes, in order: `AppHeader` (index 0),
        # its own content, then optionally a `Footer` last. Framing "its own
        # content" in a titled border means slicing those two out generically
        # here rather than each screen wrapping its own `compose()` body.
        if label is not None and len(widgets) >= 2:
            has_footer = isinstance(widgets[-1], textual.widgets.Footer)
            content_end = len(widgets) - 1 if has_footer else len(widgets)
            content = widgets[1:content_end]
            if content:
                frame = textual.containers.Container(*content)
                frame.border_title = label
                frame.add_class("-content-frame")
                widgets[1:content_end] = [frame]
        widgets.append(nav_pane.NavColumn(active_id=section_id))


class ModalScreen[T](textual.screen.ModalScreen[T]):
    @property
    def app(self) -> App:
        return super().app  # type: ignore


class Input(textual.widgets.Input):
    """Same as `textual.widgets.Input`, except focusing it doesn't select
    all of its existing text, and the cursor lands at the end instead of
    wherever it last was — the way ordinary text fields behave in most GUI
    toolkits. `checkbox_input._HintInput` is a deliberate exception (it's a
    field the user extends, not retypes) and stays on the raw Textual
    widget rather than this one."""

    def __init__(
        self,
        value: str | None = None,
        placeholder: str = "",
        *,
        password: bool = False,
        id: str | None = None,
        classes: str | None = None,
        disabled: bool = False,
        compact: bool = False,
    ) -> None:
        super().__init__(
            value,
            placeholder,
            password=password,
            select_on_focus=False,
            id=id,
            classes=classes,
            disabled=disabled,
            compact=compact,
        )

    def _on_focus(self, event: textual.events.Focus) -> None:
        super()._on_focus(event)
        self.cursor_position = len(self.value)


def format_breadcrumb(*parts: str) -> str:
    return " > ".join(parts)


BREADCRUMB_TENANTS = "Tenants"
BREADCRUMB_IDENTITIES = "Identities"
BREADCRUMB_BASTIONS = "Bastions"
BREADCRUMB_BOUNDARIES = "Boundaries"
BREADCRUMB_TAGS = "Tags"
BREADCRUMB_ROLES = "Roles"
BREADCRUMB_AUTHS = "Auths"
BREADCRUMB_AUDIT_LOG = "Audit Log"
