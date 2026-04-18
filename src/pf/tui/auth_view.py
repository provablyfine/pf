import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets
import textual_autocomplete

from .. import client
from . import auto_complete, header


def _tags_to_str(tags: list[client.schemas.TagNameValue]) -> str:
    return " ".join(f"{t.name}={t.value}" for t in tags)


def _str_to_tags(value: str) -> list[client.schemas.TagNameValue]:
    return [
        client.schemas.TagNameValue(name=k, value=v) for k, v in (s.split("=", 1) for s in value.split() if "=" in s)
    ]


class AuthViewScreen(textual.screen.Screen[None]):
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "save", "Save"),
        ("escape", "app.pop_screen", "Back"),
    ]
    DEFAULT_CSS = """
    Vertical {
        height: auto;
    }
    .field {
        border: solid;
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, a: client.schemas.Auth) -> None:
        super().__init__()
        self._auth = auth
        self._a = a
        self._saved_name: str = a.name
        self._saved_description: str = a.description
        self._saved_enabled: bool = a.is_enabled
        self._saved_tags_str: str = _tags_to_str(a.tags)

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.Vertical():
            with textual.containers.HorizontalGroup(classes="field") as c:
                c.border_title = "Name"
                yield textual.widgets.Input(self._a.name, id="name", compact=True)
            with textual.containers.HorizontalGroup(classes="field") as c:
                c.border_title = "Description"
                yield textual.widgets.Input(self._a.description, id="description", compact=True)
            with textual.containers.HorizontalGroup(classes="field") as c:
                c.border_title = "Enabled"
                yield textual.widgets.Checkbox(value=self._a.is_enabled, id="is_enabled", compact=True)
            with textual.containers.HorizontalGroup(classes="field") as c:
                c.border_title = "Tags"
                yield textual.widgets.Input(self._saved_tags_str, placeholder="name=value ...", id="tags", compact=True)
            if isinstance(self._a.config, client.schemas.OidcConfig):
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Issuer"
                    yield textual.widgets.Input(self._a.config.issuer, id="issuer", compact=True)
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Client ID"
                    yield textual.widgets.Input(self._a.config.client_id, id="client_id", compact=True)
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Client secret"
                    yield textual.widgets.Input(
                        "", placeholder="unchanged", id="client_secret", compact=True, password=True
                    )
            elif isinstance(self._a.config, client.schemas.OAuth2Config):
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Authorization endpoint"
                    yield textual.widgets.Label(self._a.config.authorization_endpoint)
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Callback URL"
                    yield textual.widgets.Label(self._a.config.callback_url)
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    @textual.work
    async def on_mount(self) -> None:
        self.sub_title = f"Auths > {self._a.name}"
        all_tags = (await self._auth.list_tags()).tags
        candidates = [textual_autocomplete.DropdownItem(main=f"{t.name}={t.value}") for t in all_tags]
        ac = auto_complete.MultiAutoComplete(self.query_one("#tags", textual.widgets.Input), candidates=candidates)
        self.screen.mount(ac)

    @textual.work
    async def action_save(self) -> None:
        name = self.query_one("#name", textual.widgets.Input).value
        description = self.query_one("#description", textual.widgets.Input).value
        is_enabled = self.query_one("#is_enabled", textual.widgets.Checkbox).value
        tags_str = self.query_one("#tags", textual.widgets.Input).value

        patch: dict = {}
        if name != self._saved_name:
            patch["name"] = name
        if description != self._saved_description:
            patch["description"] = description
        if is_enabled != self._saved_enabled:
            patch["is_enabled"] = is_enabled
        if tags_str != self._saved_tags_str:
            patch["tags"] = _str_to_tags(tags_str)

        if isinstance(self._a.config, client.schemas.OidcConfig):
            issuer = self.query_one("#issuer", textual.widgets.Input).value
            client_id = self.query_one("#client_id", textual.widgets.Input).value
            client_secret = self.query_one("#client_secret", textual.widgets.Input).value
            params_changed = issuer != self._a.config.issuer or client_id != self._a.config.client_id or client_secret
            if params_changed:
                oidc_params: dict = {"issuer": issuer, "client_id": client_id}
                if client_secret:
                    oidc_params["client_secret"] = client_secret
                patch["oidc_params"] = oidc_params

        if not patch:
            self.notify("No changes")
            return

        await self._auth.update_auth(
            self._a.id,
            name=patch.get("name"),
            description=patch.get("description"),
            is_enabled=patch.get("is_enabled"),
            tags=patch.get("tags"),
            oidc_params=patch.get("oidc_params"),
        )
        self.app.pop_screen()
