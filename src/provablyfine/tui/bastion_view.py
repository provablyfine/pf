import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets
import textual_autocomplete

from . import base, checkbox_input


def tag_filter(active: bool, value: str) -> list[pfc.schemas.TagNameValue] | None:
    """Map a Tags CheckboxInput's state to the None/[]/list tri-state.

    Unchecked -> None (visible to everyone). Checked and empty -> [] (visible to
    no one). Checked with values -> that list.
    """
    if not active:
        return None
    return [pfc.schemas.TagNameValue(name=k, value=v) for k, v in (s.split("=", 1) for s in value.split() if "=" in s)]


def tag_field_value(tag_list: list[pfc.schemas.TagNameValue] | None) -> str:
    return " ".join(f"{t.name}={t.value}" for t in (tag_list or []))


class BastionViewScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "save", "Save"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: pfc.AsyncSessionClient, bastion: pfc.schemas.Bastion) -> None:
        super().__init__()
        self._auth = auth
        self._bastion = bastion
        self._saved_url: str = bastion.url
        self._saved_ssh_proxy_jump: str | None = bastion.ssh_proxy_jump
        self._saved_tag_list: list[pfc.schemas.TagNameValue] | None = bastion.tag_list

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.Vertical():
            yield textual.widgets.Label("URL", classes="field-label -first")
            yield base.Input(self._bastion.url, id="url", compact=True)
            yield textual.widgets.Label("SSH Proxy Jump", classes="field-label")
            yield base.Input(self._bastion.ssh_proxy_jump or "", id="ssh_proxy_jump", compact=True)
            yield checkbox_input.CheckboxInput(
                "Tags",
                active=self._bastion.tag_list is not None,
                value=tag_field_value(self._bastion.tag_list),
                placeholder="Type a tag name=value",
                id="tags",
            )
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        tags_raw = (await self._auth.list_tags()).tags
        candidates = [textual_autocomplete.DropdownItem(main=f"{t.name}={t.value}") for t in tags_raw]
        self.query_one("#tags", checkbox_input.CheckboxInput).set_candidates(candidates)

    @textual.work
    async def action_save(self) -> None:
        url = self.query_one("#url", textual.widgets.Input).value
        ssh_proxy_jump = self.query_one("#ssh_proxy_jump", textual.widgets.Input).value.strip() or None
        tags_field = self.query_one("#tags", checkbox_input.CheckboxInput)
        tag_list = tag_filter(tags_field.active, tags_field.value)

        url_changed = url != self._saved_url
        ssh_proxy_jump_changed = ssh_proxy_jump != self._saved_ssh_proxy_jump
        tags_changed = tag_list != self._saved_tag_list

        if not (url_changed or ssh_proxy_jump_changed or tags_changed):
            self.notify("No changes")
            return

        update_params: dict[str, typing.Any] = {}
        if url_changed:
            update_params["url"] = url
        if ssh_proxy_jump_changed:
            update_params["ssh_proxy_jump"] = ssh_proxy_jump
        if tags_changed:
            update_params["tag_name_value_list"] = tag_list

        await self._auth.update_bastion(self._bastion.id, **update_params)
        self.app.pop_screen()
