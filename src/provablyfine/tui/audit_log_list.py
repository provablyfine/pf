import datetime
import json
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets
import textual_autocomplete

from . import auto_complete, base, clipboard

_PAGE_SIZE = 100
_POLL_SECONDS = 30


class AuditLogListScreen(base.Screen):
    """The audit log, newest first, one page at a time.

    `object_filter` is `TYPE:NAME`, or `TYPE:#ID`. With `follow`, the live object of that name is also found by id,
    so that entries from before a rename show up too.
    """

    DEFAULT_CSS = """
    AuditLogListScreen #audit-filters {
        height: 3;
    }
    AuditLogListScreen #audit-filters Input {
        width: 1fr;
    }
    AuditLogListScreen #audit-detail {
        height: auto;
        max-height: 12;
        display: none;
        border: round $primary;
    }
    """
    BINDINGS: typing.ClassVar = [
        ("escape", "back", "Back"),
        ("y", "copy", "Copy"),
        ("r", "reload", "Reload"),
        ("ctrl+f", "toggle_follow", "Follow"),
        ("ctrl+u", "clear_filters", "Clear"),
    ]

    def __init__(
        self,
        auth: pfc.AsyncSessionClient,
        object_filter: str = "",
        by_identity: str = "",
        follow: bool = False,
    ) -> None:
        super().__init__()
        self._auth = auth
        self._initial_object = object_filter
        self._initial_by = by_identity
        self._follow = follow
        self._entries: list[pfc.schemas.AuditLogEntry] = []
        self._cursor: str | None = None
        self._newest_id: int | None = None
        self._loading = False
        # Object type -> actions, as the server knows them. Filled when the screen opens.
        self._actions_by_type: dict[str, list[str]] = {}

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.Horizontal(id="audit-filters"):
            for input_id, title, value in (
                ("object", "object", self._initial_object),
                ("by", "by", self._initial_by),
                ("types", "object types", ""),
                ("actions", "actions", ""),
                ("level", "level", ""),
            ):
                widget = base.Input(value, placeholder="all", compact=True, id=f"audit-{input_id}")
                widget.border_title = title
                yield widget
        yield textual.widgets.DataTable(cursor_type="row", id="audit-table")
        yield textual.widgets.Label("No audit log entries", id="audit-log-placeholder")
        yield textual.widgets.Static(id="audit-detail")
        yield auto_complete.MultiAutoComplete("#audit-types", candidates=self._object_type_candidates)
        yield auto_complete.MultiAutoComplete("#audit-actions", candidates=self._action_candidates)
        yield auto_complete.MonoAutoComplete(
            "#audit-level",
            candidates=[textual_autocomplete.DropdownItem(main=v) for v in ("all", "warn", "info")],
        )
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    def _object_type_candidates(
        self, state: textual_autocomplete.TargetState
    ) -> list[textual_autocomplete.DropdownItem]:
        return [textual_autocomplete.DropdownItem(main=t) for t in self._actions_by_type]

    def _action_candidates(self, state: textual_autocomplete.TargetState) -> list[textual_autocomplete.DropdownItem]:
        """The actions of the object types already chosen, or all of them when none is."""
        chosen = [t for t in self._input("types").split() if t in self._actions_by_type]
        types = chosen or list(self._actions_by_type)
        actions = dict.fromkeys(a for t in types for a in self._actions_by_type[t])
        return [textual_autocomplete.DropdownItem(main=a) for a in actions]

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        table.add_columns("Time", "Level", "Type", "By", "About")
        try:
            types = await self._auth.list_audit_log_types()
            self._actions_by_type = {t.object_type: t.actions for t in types.object_types}
        except pfc.exceptions.UI as e:
            # Filtering by hand still works without the completion.
            self.notify(str(e), severity="warning")
        self._update_follow_title()
        self.set_interval(_POLL_SECONDS, self._poll)
        await self._reload()

    def _update_follow_title(self) -> None:
        title = "object · follow" if self._follow else "object"
        self.query_one("#audit-object").border_title = title

    def _input(self, name: str) -> str:
        return self.query_one(f"#audit-{name}", textual.widgets.Input).value.strip()

    async def _filters(self) -> list[dict[str, typing.Any]]:
        """One set of query parameters per query to make. Several only when following a rename."""
        common: dict[str, typing.Any] = {}
        types = self._input("types").split()
        if types:
            common["object_type"] = types
        actions = self._input("actions").split()
        if actions:
            common["action"] = actions
        level = self._input("level")
        if level in ("warn", "info"):
            common["level"] = 2 if level == "warn" else 1
        by = self._input("by")
        if by:
            if by.isdigit():
                common["by_identity_id"] = by
            else:
                found = (await self._auth.list_identities(name=by)).identities
                common["by_identity_id"] = str(found[0].id) if found else "-1"
        object_filter = self._input("object")
        if not object_filter:
            return [common]
        object_type, _, name = object_filter.partition(":")
        if not name:
            return [{**common, "ref_type": object_type}]
        if name.startswith("#"):
            # `TYPE:#ID` is one object, by id. It is found under every name it has had.
            return [{**common, "ref_type": object_type, "ref_id": name[1:]}]
        queries = [{**common, "ref_type": object_type, "ref_name": name}]
        if self._follow:
            for object_id in await self._auth.find_object_ids(object_type, name):
                queries.append({**common, "ref_type": object_type, "ref_id": object_id})
        return queries

    async def _reload(self) -> None:
        if self._loading:
            return
        self._loading = True
        try:
            queries = await self._filters()
            if len(queries) == 1:
                page = await self._auth.list_audit_log(**queries[0], limit=_PAGE_SIZE)
                self._entries = page.entries
                self._cursor = page.next_cursor
            else:
                # A cursor cannot span several queries, so each is read to its end and the results are merged.
                merged: dict[int, pfc.schemas.AuditLogEntry] = {}
                for query in queries:
                    cursor: str | None = None
                    while True:
                        page = await self._auth.list_audit_log(**query, limit=1000, cursor=cursor)
                        merged.update((e.id, e) for e in page.entries)
                        cursor = page.next_cursor
                        if cursor is None:
                            break
                self._entries = sorted(merged.values(), key=lambda e: e.id, reverse=True)
                self._cursor = None
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            return
        finally:
            self._loading = False
        self._newest_id = self._entries[0].id if self._entries else None
        table = self.query_one(textual.widgets.DataTable[str])
        table.clear(columns=False)
        self._add_rows(self._entries)
        self.query_one("#audit-log-placeholder").display = not bool(self._entries)
        self._update_table_title()
        self._show_detail()

    async def _load_more(self) -> None:
        if self._cursor is None or self._loading:
            return
        self._loading = True
        try:
            queries = await self._filters()
            page = await self._auth.list_audit_log(**queries[0], limit=_PAGE_SIZE, cursor=self._cursor)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            return
        finally:
            self._loading = False
        self._entries.extend(page.entries)
        self._cursor = page.next_cursor
        self._add_rows(page.entries)
        self._update_table_title()

    def _add_rows(self, entries: list[pfc.schemas.AuditLogEntry]) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        for entry in entries:
            level = "[bold red]WARN[/]" if entry.level == 2 else "INFO"
            at = datetime.datetime.fromtimestamp(entry.at).strftime("%Y-%m-%d %H:%M:%S")
            by = entry.by_identity_name or entry.by_identity_id or ""
            about = ", ".join(f"{r.type}:{r.name or r.id}" for r in entry.refs[:2])
            table.add_row(at, level, entry.type, by, about, key=str(entry.id))

    def _update_table_title(self, banner: str = "") -> None:
        more = "+" if self._cursor is not None else ""
        self.query_one(textual.widgets.DataTable[str]).border_title = f"{len(self._entries)}{more} loaded{banner}"

    async def _poll(self) -> None:
        if self.app.screen is not self or self._loading:
            return
        try:
            queries = await self._filters()
            page = await self._auth.list_audit_log(**queries[0], limit=1)
        except pfc.exceptions.UI:
            return
        if page.entries and (self._newest_id is None or page.entries[0].id > self._newest_id):
            self._update_table_title(" · new entries, press r")

    def _selected(self) -> pfc.schemas.AuditLogEntry | None:
        table = self.query_one(textual.widgets.DataTable[str])
        if not self._entries or table.cursor_row >= len(self._entries):
            return None
        return self._entries[table.cursor_row]

    def _show_detail(self) -> None:
        detail = self.query_one("#audit-detail", textual.widgets.Static)
        entry = self._selected()
        if entry is None:
            detail.display = False
            return
        at = datetime.datetime.fromtimestamp(entry.at).strftime("%Y-%m-%d %H:%M:%S")
        level = "WARN" if entry.level == 2 else "INFO"
        lines = [f"{at}  {level}  {entry.type}  (entry {entry.id})"]
        by = entry.by_identity_name or entry.by_identity_id
        if by:
            lines.append(f"by    {by}" + (f" (id {entry.by_identity_id})" if entry.by_identity_name else ""))
        lines.extend(f"refs  {r.type} {r.name or ''} (id {r.id})" for r in entry.refs)
        skipped = {"refs", "old"}
        old = entry.details.get("old")
        if old is not None:
            lines.append(f"old   {_short(old)}")
        for key, value in entry.details.items():
            if key not in skipped:
                lines.append(f"{key:<5} {_short(value)}")
        detail.update("\n".join(lines))
        detail.display = True

    @textual.on(textual.widgets.DataTable.RowHighlighted)
    async def _on_row_highlighted(self) -> None:
        self._show_detail()
        table = self.query_one(textual.widgets.DataTable[str])
        if self._entries and table.cursor_row >= len(self._entries) - 1:
            await self._load_more()

    @textual.on(textual.widgets.Input.Submitted)
    async def _on_filter_submitted(self) -> None:
        await self._reload()
        self.query_one(textual.widgets.DataTable[str]).focus()

    async def action_reload(self) -> None:
        await self._reload()

    async def action_toggle_follow(self) -> None:
        self._follow = not self._follow
        self._update_follow_title()
        await self._reload()

    async def action_clear_filters(self) -> None:
        for name in ("object", "by", "types", "actions", "level"):
            self.query_one(f"#audit-{name}", textual.widgets.Input).value = ""
        await self._reload()

    async def action_copy(self) -> None:
        entry = self._selected()
        if entry is None:
            return
        await clipboard.copy(self.app, json.dumps(entry.model_dump(), indent=2))
        self.notify("Entry copied")

    def action_back(self) -> None:
        if isinstance(self.focused, textual.widgets.Input):
            self.query_one(textual.widgets.DataTable[str]).focus()
            return
        self.app.pop_screen()


def _short(value: object) -> str:
    text = json.dumps(value) if not isinstance(value, str) else value
    return text if len(text) <= 100 else text[:97] + "..."
