import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.reactive
import textual.screen
import textual.widgets

from .. import base as tui_base
from .. import header
from . import base, boundary, identity, role, ssh, tag, tenant


class GrantEditScreen(textual.screen.Screen[pfc.schemas.Grant | None]):
    DEFAULT_CSS = """
    .sections {
        padding: 0 1;
    }
    #dynamic-grant-fields {
        /* Container is 1fr, which would fill .sections exactly and clip its
           own overflow, leaving the scrollbar above it nothing to scroll. */
        height: auto;
    }
    .section {
        padding: 1 0 0 0;
    }
    .label {
        padding: 0 0;
    }
    """
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "confirm", "Confirm"),
        ("escape", "cancel", "Cancel"),
        ("up", "app.focus_previous", ""),
        ("down", "app.focus_next", ""),
    ]
    grant_type: textual.reactive.Reactive[str] = textual.reactive.Reactive("")

    def __init__(self, auth: pfc.AsyncSessionClient, grant: pfc.schemas.Grant, parent_breadcrumb: str):
        super().__init__(id="grant-edit")
        self._auth = auth
        self._grant = grant
        self._parent_breadcrumb = parent_breadcrumb
        self.grant_type = grant.type

    async def watch_grant_type(self, value: str) -> None:
        self.sub_title = tui_base.format_breadcrumb(self._parent_breadcrumb, f"Edit {value} grant")
        fields = self.query_one("#dynamic-grant-fields")
        await fields.query("*").remove()
        match value:
            case "role":
                widget = role.RoleGrantEditWidget(self._auth, typing.cast(pfc.schemas.RoleGrant, self._grant))
            case "identity":
                widget = identity.IdentityGrantEditWidget(
                    self._auth, typing.cast(pfc.schemas.IdentityGrant, self._grant)
                )
            case "tag":
                widget = tag.TagGrantEditWidget(self._auth, typing.cast(pfc.schemas.TagGrant, self._grant))
            case "boundary":
                widget = boundary.BoundaryGrantEditWidget(
                    self._auth, typing.cast(pfc.schemas.BoundaryGrant, self._grant)
                )
            case "tenant":
                widget = tenant.TenantGrantEditWidget(self._auth, typing.cast(pfc.schemas.TenantGrant, self._grant))
            case "ssh":
                widget = ssh.SshGrantEditWidget(self._auth, typing.cast(pfc.schemas.SSHGrant, self._grant))
            case _:
                return
        await fields.mount(widget)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_confirm(self) -> None:
        widgets = list(self.query_one("#dynamic-grant-fields").query(base.GrantEditWidget))
        if not widgets:
            return
        try:
            grant = widgets[0].get_grant_data()
        except pfc.exceptions.UI as e:
            # Report and stay: dismissing would throw away the edits the user
            # now has to correct.
            self.notify(str(e), severity="error")
            return
        self.dismiss(grant)

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        # A grant with more commands than the terminal has lines must scroll
        # rather than lose its tail. Not a focus stop of its own: up/down are
        # the screen's focus chain, and moving along it scrolls the field that
        # gains focus into view.
        sections = textual.containers.VerticalScroll(classes="sections")
        sections.can_focus = False
        with sections:
            yield textual.containers.Container(id="dynamic-grant-fields")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)
