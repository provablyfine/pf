from __future__ import annotations

import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets

from . import base


class AuthViewScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "save", "Save"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: pfc.AsyncSessionClient, a: pfc.schemas.Auth) -> None:
        super().__init__()
        self._auth = auth
        self._a = a
        self._saved_name: str = a.name
        self._saved_description: str = a.description
        self._saved_enabled: bool = a.is_enabled
        self._saved_require_email_verified: bool | None = (
            a.config.require_email_verified if isinstance(a.config, pfc.schemas.OidcConfig) else None
        )

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.Vertical():
            yield textual.widgets.Label("Name", classes="field-label -first")
            yield base.Input(self._a.name, id="name", compact=True)
            yield textual.widgets.Label("Description", classes="field-label")
            yield base.Input(self._a.description, id="description", compact=True)
            yield textual.widgets.Label("Enabled", classes="field-label")
            yield textual.widgets.Checkbox(value=self._a.is_enabled, id="is_enabled", compact=True)
            if isinstance(self._a.config, pfc.schemas.OidcConfig):
                yield textual.widgets.Label("Issuer", classes="field-label")
                yield base.Input(self._a.config.issuer, id="issuer", compact=True, disabled=True)
                yield textual.widgets.Label("Client ID", classes="field-label")
                yield base.Input(self._a.config.client_id, id="client_id", compact=True, disabled=True)
                yield textual.widgets.Label("Client secret", classes="field-label")
                yield base.Input(
                    "", placeholder="unchanged", id="client_secret", compact=True, password=True, disabled=True
                )
                yield textual.widgets.Label("Require verified email", classes="field-label")
                yield textual.widgets.Checkbox(
                    value=self._a.config.require_email_verified, id="require_email_verified", compact=True
                )
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    @textual.work
    async def action_save(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value
        description = self.query_one("#description", textual.widgets.Input).value
        is_enabled = self.query_one("#is_enabled", textual.widgets.Checkbox).value

        name_changed = name != self._saved_name
        description_changed = description != self._saved_description
        is_enabled_changed = is_enabled != self._saved_enabled

        require_email_verified: bool | None = None
        require_email_verified_changed = False
        if self._saved_require_email_verified is not None:
            require_email_verified = self.query_one("#require_email_verified", textual.widgets.Checkbox).value
            require_email_verified_changed = require_email_verified != self._saved_require_email_verified

        if not (name_changed or description_changed or is_enabled_changed or require_email_verified_changed):
            self.notify("No changes")
            return

        await self._auth.update_auth(
            self._a.id,
            name=name if name_changed else None,
            description=description if description_changed else None,
            is_enabled=is_enabled if is_enabled_changed else None,
            require_email_verified=require_email_verified if require_email_verified_changed else None,
        )
        self.app.pop_screen()
