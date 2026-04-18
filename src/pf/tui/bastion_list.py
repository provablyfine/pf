import typing

import textual
import textual.app
import textual.containers
import textual.screen
import textual.widgets

from .. import client
from . import base, bastion_view, header


class _BastionCreateScreen(textual.screen.ModalScreen[dict | None]):
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
            yield textual.widgets.Input(placeholder="register_url", id="register_url", compact=True)
            yield textual.widgets.Input(placeholder="connect_url (optional)", id="connect_url", compact=True)
            yield textual.widgets.Input(placeholder="ssh_proxy_jump (optional)", id="ssh_proxy_jump", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submit(self) -> None:
        register_url = self.query_one("#register_url", textual.widgets.Input).value.strip()
        if not register_url:
            return
        connect_url = self.query_one("#connect_url", textual.widgets.Input).value.strip() or None
        ssh_proxy_jump = self.query_one("#ssh_proxy_jump", textual.widgets.Input).value.strip() or None
        self.dismiss(
            {
                "register_url": register_url,
                "connect_url": connect_url,
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

    def __init__(self, auth: client.aio.Client) -> None:
        super().__init__()
        self._auth = auth
        self._bastions: list[client.schemas.Bastion] = []

    def compose(self) -> textual.app.ComposeResult:
        yield header.AppHeader()
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable)
        table.add_columns("Register URL", "Connect URL", "Tags")
        self._bastions = (await self._auth.list_bastions()).bastions
        self._populate_table(table)

    @textual.work
    async def on_screen_resume(self) -> None:
        self._bastions = (await self._auth.list_bastions()).bastions
        self._populate_table(self.query_one(textual.widgets.DataTable))

    def _populate_table(self, table: textual.widgets.DataTable) -> None:
        table.clear(columns=False)
        for bastion in self._bastions:
            table.add_row(
                bastion.register_url,
                bastion.connect_url or "",
                str(len(bastion.tag_list)),
            )

    @textual.on(textual.widgets.DataTable.RowSelected)
    def _on_row_selected(self) -> None:
        self.action_view_bastion()

    def action_view_bastion(self) -> None:
        if not self._bastions:
            return
        table = self.query_one(textual.widgets.DataTable)
        bastion = self._bastions[table.cursor_row]
        self.app.push_screen(bastion_view.BastionViewScreen(self._auth, bastion))

    @textual.work
    async def action_add_bastion(self) -> None:
        result = await self.app.push_screen_wait(_BastionCreateScreen())
        if result is None:
            return
        bastion = await self._auth.create_bastion(
            result["register_url"],
            result["connect_url"],
            result["ssh_proxy_jump"],
            [],
            [],
        )
        self._bastions.append(bastion)
        table = self.query_one(textual.widgets.DataTable)
        self._populate_table(table)
        table.move_cursor(row=len(self._bastions) - 1)
        self.app.push_screen(bastion_view.BastionViewScreen(self._auth, bastion))

    @textual.work
    async def action_delete_bastion(self) -> None:
        if not self._bastions:
            return
        table = self.query_one(textual.widgets.DataTable)
        index = table.cursor_row
        bastion = self._bastions[index]
        await self._auth.delete_bastion(bastion.id)
        self._bastions.pop(index)
        self._populate_table(table)
        self.notify(f"Bastion '{bastion.register_url}' deleted")
