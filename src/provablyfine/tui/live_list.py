import datetime
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.widgets

from . import base


def _time(at: int | None) -> str:
    return "" if at is None else datetime.datetime.fromtimestamp(at).strftime("%Y-%m-%d %H:%M:%S")


class _ConfirmScreen(base.ModalScreen[bool]):
    BINDINGS: typing.ClassVar = [("y", "yes", "Yes"), ("n,escape", "no", "No")]

    def __init__(self, question: str) -> None:
        super().__init__()
        self._question = question

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.Label(f"{self._question} (y/n)")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


class LiveListScreen(base.Screen):
    BINDINGS: typing.ClassVar = [
        ("k", "terminate", "End session"),
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, auth: pfc.AsyncSessionClient) -> None:
        super().__init__()
        self._auth = auth
        self._sessions: list[pfc.schemas.LiveSession] = []

    def compose(self) -> textual.app.ComposeResult:
        yield textual.widgets.DataTable(cursor_type="row")
        yield textual.widgets.Label("No live sessions", id="live-placeholder")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    @textual.work
    async def on_mount(self) -> None:
        self.query_one(textual.widgets.DataTable[str]).add_columns("Host", "Kind", "Identity", "Started", "Deadline")
        await self._refresh()

    @textual.work
    async def on_screen_resume(self) -> None:
        await self._refresh()

    async def _refresh(self) -> None:
        self._sessions = (await self._auth.list_live(active=True)).sessions
        table = self.query_one(textual.widgets.DataTable[str])
        table.clear(columns=False)
        for s in self._sessions:
            table.add_row(s.hostname, s.kind, str(s.identity_id), _time(s.started_at), _time(s.deadline))
        self.query_one("#live-placeholder").display = not bool(self._sessions)

    @textual.work
    async def action_terminate(self) -> None:
        if not self._sessions:
            return
        session = self._sessions[self.query_one(textual.widgets.DataTable[str]).cursor_row]
        if not await self.app.push_screen_wait(
            _ConfirmScreen(f"End the {session.kind} session on {session.hostname}?")
        ):
            return
        await self._auth.terminate_live(session.id)
        self.notify(f"Session on '{session.hostname}' ended")
        await self._refresh()
