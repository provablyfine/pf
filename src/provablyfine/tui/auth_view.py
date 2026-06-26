from __future__ import annotations

import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets
import textual_autocomplete

from . import auto_complete, base, header


def _tags_to_str(tags: list[pfc.schemas.TagNameValue]) -> str:
    return " ".join(f"{t.name}={t.value}" for t in tags)


def _str_to_tags(value: str) -> list[pfc.schemas.TagNameValue]:
    return [pfc.schemas.TagNameValue(name=k, value=v) for k, v in (s.split("=", 1) for s in value.split() if "=" in s)]


class AuthViewScreen(base.Screen):
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

    def __init__(self, auth: pfc.AsyncSessionClient, a: pfc.schemas.Auth) -> None:
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
            if isinstance(self._a.config, pfc.schemas.OidcConfig):
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Issuer"
                    yield textual.widgets.Input(self._a.config.issuer, id="issuer", compact=True, disabled=True)
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Client ID"
                    yield textual.widgets.Input(self._a.config.client_id, id="client_id", compact=True, disabled=True)
                with textual.containers.HorizontalGroup(classes="field") as c:
                    c.border_title = "Client secret"
                    yield textual.widgets.Input(
                        "", placeholder="unchanged", id="client_secret", compact=True, password=True, disabled=True
                    )
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

        name_changed = name != self._saved_name
        description_changed = description != self._saved_description
        is_enabled_changed = is_enabled != self._saved_enabled
        tags_changed = tags_str != self._saved_tags_str

        if not (name_changed or description_changed or is_enabled_changed or tags_changed):
            self.notify("No changes")
            return

        await self._auth.update_auth(
            self._a.id,
            name=name if name_changed else None,
            description=description if description_changed else None,
            is_enabled=is_enabled if is_enabled_changed else None,
            tags=_str_to_tags(tags_str) if tags_changed else None,
        )
        self.app.pop_screen()
