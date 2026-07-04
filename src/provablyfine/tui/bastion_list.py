import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from . import base, bastion_view, header


class _BastionFormResult(typing.TypedDict):
    url: str
    ssh_proxy_jump: str | None


class _BastionCreateScreen(textual.screen.ModalScreen[_BastionFormResult | None]):
    DEFAULT_CSS = """
    _BastionCreateScreen {
        align: center middle;
    }
    _BastionCreateScreen > VerticalGroup {
        width: 50;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
    }
    """
    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as container:
            container.border_title = "Add a bastion"
            yield textual.widgets.Input(placeholder="url", id="url", compact=True)
            yield textual.widgets.Input(placeholder="ssh_proxy_jump (optional)", id="ssh_proxy_jump", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        url = self.query_one("#url", textual.widgets.Input).value.strip()
        if not url:
            return
        ssh_proxy_jump = self.query_one("#ssh_proxy_jump", textual.widgets.Input).value.strip() or None
        self.dismiss(
            {
                "url": url,
                "ssh_proxy_jump": ssh_proxy_jump,
            }
        )


class BastionListScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("enter", "view_bastion", "View"),
        ("a", "add_bastion", "Add"),
        ("d", "delete_bastion", "Delete"),
        ("escape", "app.pop_screen", "Back"),
    ]

    class _StrDataTable(textual.widgets.DataTable[str]):
        pass

    def __init__(self, auth: pfc.AsyncSessionClient) -> None:
        super().__init__()
        self._auth = auth
        self._bastions: list[pfc.schemas.Bastion] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield self._StrDataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(self._StrDataTable)
        table.add_columns("URL", "SSH Proxy Jump", "Tags")
        self._bastions = (await self._auth.list_bastions()).bastions
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._bastions = (await self._auth.list_bastions()).bastions
        self._populate_table(self.query_one(self._StrDataTable))

    def _populate_table(self, table: "BastionListScreen._StrDataTable") -> None:
        table.clear(columns=False)
        for bastion in self._bastions:
            table.add_row(
                bastion.url,
                bastion.ssh_proxy_jump or "",
                str(len(bastion.tag_list)),
            )

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_bastion()

    def action_view_bastion(self) -> None:
        if not self._bastions:
            return
        table = self.query_one(self._StrDataTable)
        bastion = self._bastions[table.cursor_row]
        self.app.push_screen(bastion_view.BastionViewScreen(self._auth, bastion))

    @textual.work
    async def action_add_bastion(self) -> None:
        result = await self.app.push_screen_wait(_BastionCreateScreen())
        if result is None:
            return
        bastion = await self._auth.create_bastion(
            result["url"],
            result["ssh_proxy_jump"],
            [],
            [],
        )
        self._bastions.append(bastion)
        table = self.query_one(self._StrDataTable)
        self._populate_table(table)
        table.move_cursor(row=len(self._bastions) - 1)
        self.app.push_screen(bastion_view.BastionViewScreen(self._auth, bastion))

    @textual.work
    async def action_delete_bastion(self) -> None:
        if not self._bastions:
            return
        table = self.query_one(self._StrDataTable)
        index = table.cursor_row
        bastion = self._bastions[index]
        await self._auth.delete_bastion(bastion.id)
        self._bastions.pop(index)
        self._populate_table(table)
        self.notify(f"Bastion '{bastion.url}' deleted")
