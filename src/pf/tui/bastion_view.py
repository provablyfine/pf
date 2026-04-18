import typing

import textual
import textual.app
import textual.containers
import textual.events
import textual.screen
import textual.widgets
import textual_autocomplete

from .. import client
from . import auto_complete, base, header


class _TagAddScreen(textual.screen.ModalScreen[client.schemas.TagNameValue | None]):
    DEFAULT_CSS = """
    _TagAddScreen {
        align: center middle;
    }
    _TagAddScreen > VerticalGroup {
        width: 50;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def __init__(self, tags: list[client.schemas.TagNameValue]) -> None:
        super().__init__()
        self._tags: dict[str, client.schemas.TagNameValue] = {f"{t.name}={t.value}": t for t in tags}

    def compose(self) -> textual.app.ComposeResult:
        candidates = [textual_autocomplete.DropdownItem(main=label) for label in self._tags]
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Add tag"
            yield textual.widgets.Input(placeholder="name=value", compact=True, id="tag-input")
        yield auto_complete.MonoAutoComplete("#tag-input", candidates=candidates)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        value = self.query_one("#tag-input", textual.widgets.Input).value.strip()
        tag = self._tags.get(value)
        if tag is None:
            return
        self.dismiss(tag)


class BastionViewScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("ctrl+s", "save", "Save"),
        ("escape", "app.pop_screen", "Back"),
        ("a", "add_tag", "Add tag"),
        ("d", "delete_tag", "Delete tag"),
    ]
    DEFAULT_CSS = """
    Vertical {
        height: auto;
    }
    .field {
        border: solid;
        height: auto;
    }
    #tags {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, bastion: client.schemas.Bastion) -> None:
        super().__init__()
        self._auth = auth
        self._bastion = bastion
        self._tags: list[client.schemas.TagNameValue] = list(bastion.tag_list)
        self._saved_register_url: str = bastion.register_url
        self._saved_connect_url: str | None = bastion.connect_url
        self._saved_ssh_proxy_jump: str | None = bastion.ssh_proxy_jump
        self._saved_tags: list[client.schemas.TagNameValue] = list(bastion.tag_list)

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.Vertical():
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "Register URL"
                yield textual.widgets.Input(self._bastion.register_url, id="register_url", compact=True)
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "Connect URL"
                yield textual.widgets.Input(self._bastion.connect_url or "", id="connect_url", compact=True)
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "SSH Proxy Jump"
                yield textual.widgets.Input(self._bastion.ssh_proxy_jump or "", id="ssh_proxy_jump", compact=True)
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "Token"
                token = getattr(self._bastion, "token", None) or "—"
                yield textual.widgets.Label(token, id="token")
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "IP Addresses"
                ip_list_attr = getattr(self._bastion, "ip_address_list", None)
                ip_list = ", ".join(ip_list_attr) if ip_list_attr else "—"
                yield textual.widgets.Label(ip_list, id="ip_address_list")
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Tags"
                yield textual.widgets.ListView(id="tags")
                yield textual.widgets.Label("No tags — add one with 'a'", id="tags-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        self.sub_title = f"Bastions > {self._bastion.register_url}"
        await self._populate_tags()

    def on_descendant_focus(self, event: textual.events.DescendantFocus) -> None:
        self.refresh_bindings()

    def on_descendant_blur(self, event: textual.events.DescendantBlur) -> None:
        self.refresh_bindings()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in ("add_tag", "delete_tag"):
            focused = self.focused
            return focused is not None and focused.id == "tags"
        return True

    async def _populate_tags(self) -> None:
        lv = self.query_one("#tags", textual.widgets.ListView)
        await lv.clear()
        for tag in self._tags:
            await lv.append(textual.widgets.ListItem(textual.widgets.Label(f"{tag.name}={tag.value}")))
        self.query_one("#tags-placeholder").display = not bool(self._tags)

    @textual.work
    async def action_add_tag(self) -> None:
        all_tags = (await self._auth.list_tags()).tags
        existing = {(t.name, t.value) for t in self._tags}
        available = [
            client.schemas.TagNameValue(name=t.name, value=t.value)
            for t in all_tags
            if (t.name, t.value) not in existing
        ]
        if not available:
            self.notify("No tag available to add")
            return
        tag = await self.app.push_screen_wait(_TagAddScreen(available))
        if tag is None:
            return
        self._tags.append(tag)
        await self._populate_tags()

    @textual.work
    async def action_delete_tag(self) -> None:
        lv = self.query_one("#tags", textual.widgets.ListView)
        index = lv.index
        if index is None or not self._tags:
            return
        self._tags.pop(index)
        await self._populate_tags()

    @textual.work
    async def action_save(self) -> None:
        register_url = self.query_one("#register_url", textual.widgets.Input).value
        connect_url = self.query_one("#connect_url", textual.widgets.Input).value.strip() or None
        ssh_proxy_jump = self.query_one("#ssh_proxy_jump", textual.widgets.Input).value.strip() or None

        update_kwargs: dict[str, object] = {}
        if register_url != self._saved_register_url:
            update_kwargs["register_url"] = register_url
        if connect_url != self._saved_connect_url:
            update_kwargs["connect_url"] = connect_url
        if ssh_proxy_jump != self._saved_ssh_proxy_jump:
            update_kwargs["ssh_proxy_jump"] = ssh_proxy_jump
        if self._tags != self._saved_tags:
            update_kwargs["tag_name_value_list"] = self._tags

        if not update_kwargs:
            self.notify("No changes")
            return

        await self._auth.update_bastion(self._bastion.id, **update_kwargs)  # type: ignore[arg-type]
        self.app.pop_screen()
