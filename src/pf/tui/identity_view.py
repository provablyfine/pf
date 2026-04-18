import typing

import textual
import textual.app
import textual.containers
import textual.events
import textual.screen
import textual.widgets
import textual_autocomplete

from .. import client
from . import auto_complete, header


class _TagAddScreen(textual.screen.ModalScreen[dict | None]):
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

    def __init__(self, tags: list[dict]) -> None:
        super().__init__()
        self._tags = {f"{t['name']}={t['value']}": t for t in tags}

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


class IdentityViewScreen(textual.screen.Screen[None]):
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
    #tags, #boundaries {
        height: auto;
    }
    """

    def __init__(self, auth: client.aio.Client, identity: client.schemas.Identity) -> None:
        super().__init__()
        self._auth = auth
        self._identity = identity
        self._tags: list[client.schemas.Tag] = list(identity.tags)
        self._saved_name: str = identity.name
        self._saved_tag_ids: list[int] = [t.id for t in identity.tags]

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        with textual.containers.Vertical():
            with textual.containers.HorizontalGroup(classes="field") as container:
                container.border_title = "Name"
                yield textual.widgets.Input(self._identity.name, id="name", compact=True)
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Tags"
                yield textual.widgets.ListView(id="tags")
                yield textual.widgets.Label("No tags — add one with 'a'", id="tags-placeholder")
            with textual.containers.Container(classes="field") as container:
                container.border_title = "Boundaries"
                yield textual.widgets.ListView(id="boundaries")
                yield textual.widgets.Label("No boundaries", id="boundaries-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        self.sub_title = f"Identities > {self._identity.name}"
        await self._populate_tags()
        await self._populate_boundaries()

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

    async def _populate_boundaries(self) -> None:
        lv = self.query_one("#boundaries", textual.widgets.ListView)
        await lv.clear()
        for b in self._identity.boundaries:
            await lv.append(textual.widgets.ListItem(textual.widgets.Label(b.name)))
        self.query_one("#boundaries-placeholder").display = not bool(self._identity.boundaries)

    @textual.work
    async def action_add_tag(self) -> None:
        all_tags = (await self._auth.list_tags()).tags
        existing_ids = {t.id for t in self._tags}
        available = [{"id": t.id, "name": t.name, "value": t.value} for t in all_tags if t.id not in existing_ids]
        if not available:
            self.notify("No tags available to add")
            return
        tag = await self.app.push_screen_wait(_TagAddScreen(available))
        if tag is None:
            return
        self._tags.append(client.schemas.Tag(id=tag["id"], name=tag["name"], value=tag["value"]))
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
        name = self.query_one("#name", textual.widgets.Input).value
        current_tag_ids = [t.id for t in self._tags]

        patch: dict = {}
        if name != self._saved_name:
            patch["name"] = name
        if current_tag_ids != self._saved_tag_ids:
            patch["tags"] = [{"type": "set", "tag_id_list": current_tag_ids}]

        if not patch:
            self.notify("No changes")
            return

        tags = None
        if "tags" in patch:
            tags = [client.schemas.IdentityTagOp.model_validate(t) for t in patch["tags"]]

        await self._auth.update_identity(
            self._identity.id,
            name=patch.get("name"),
            tags=tags,
        )
        self.app.pop_screen()
