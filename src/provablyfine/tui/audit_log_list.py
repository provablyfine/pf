import dataclasses
import datetime
import json
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.widgets

from . import base, clipboard, multi_select

_PAGE_SIZE = 100
_POLL_SECONDS = 30


@dataclasses.dataclass(frozen=True)
class _Bar:
    """What the filter bar holds. The rows on screen were read with one of these."""

    object: str
    by: str
    types: tuple[str, ...]
    actions: tuple[str, ...]
    levels: tuple[str, ...]
    follow: bool

    def describe(self) -> str:
        parts: list[str] = []
        if self.object:
            parts.append(self.object + (" (follow)" if self.follow else ""))
        if self.by:
            parts.append(f"by {self.by}")
        if self.types:
            parts.append(",".join(self.types))
        if self.actions:
            parts.append(",".join(self.actions))
        if self.levels:
            parts.append(",".join(self.levels))
        return " ".join(parts) or "no filters"


class AuditLogListScreen(base.Screen):
    """The audit log, newest first, one page at a time.

    `object_filter` is `TYPE:NAME`, or `TYPE:#ID`.
    With `follow`, the entries about every object that ever had that name are shown,
    so that entries from before and after a rename show up together.
    """

    DEFAULT_CSS = """
    AuditLogListScreen #audit-filters {
        height: 3;
    }
    AuditLogListScreen #audit-filters Input {
        width: 1fr;
    }
    AuditLogListScreen #audit-filters Input.-edited {
        color: $warning;
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
        # Every reload takes a number. An answer that is not for the latest one is dropped.
        self._generation = 0
        self._page_size = _PAGE_SIZE
        # The filters of the rows on screen. Paging and polling use them, whatever the bar says now.
        self._applied_bar = _Bar("", "", (), (), (), follow)
        self._applied_query: dict[str, typing.Any] = {}
        self._new_entries = False
        # Object type -> actions, as the server knows them. Filled when the screen opens.
        self._actions_by_type: dict[str, list[str]] = {}

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.Horizontal(id="audit-filters"):
            for input_id, title, value in (
                ("object", "object", self._initial_object),
                ("by", "by", self._initial_by),
            ):
                widget = base.Input(value, placeholder=title, compact=True, id=f"audit-{input_id}")
                widget.border_title = title
                yield widget
            yield multi_select.MultiSelect("types", id="audit-types")
            yield multi_select.MultiSelect("actions", id="audit-actions")
            yield multi_select.MultiSelect("level", id="audit-level")
        yield textual.widgets.DataTable(cursor_type="row", id="audit-table")
        yield textual.widgets.Label("No audit log entries", id="audit-log-placeholder")
        yield textual.widgets.Static(id="audit-detail")
        yield textual.widgets.Footer(compact=True, show_command_palette=False)

    def _select(self, name: str) -> multi_select.MultiSelect:
        return self.query_one(f"#audit-{name}", multi_select.MultiSelect)

    def _action_options(self) -> list[str]:
        """The actions of the object types already chosen, or all of them when none is."""
        chosen = [t for t in self._select("types").selected if t in self._actions_by_type]
        types = chosen or list(self._actions_by_type)
        return list(dict.fromkeys(a for t in types for a in self._actions_by_type[t]))

    async def on_mount(self) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        table.add_columns("Time", "Level", "Type", "By", "About")
        try:
            types = await self._auth.list_audit_log_types()
            self._actions_by_type = {t.object_type: t.actions for t in types.object_types}
        except pfc.exceptions.UI as e:
            # The type and action lists stay empty. The other filters still work.
            self.notify(str(e), severity="warning")
        self._select("types").set_options(list(self._actions_by_type))
        self._select("actions").set_options(self._action_options())
        self._select("level").set_options(["info", "warn"])
        self._update_follow_title()
        self.set_interval(_POLL_SECONDS, self._poll)
        await self._reload()

    def _update_follow_title(self) -> None:
        title = "object · follow" if self._follow else "object"
        self.query_one("#audit-object").border_title = title

    def _input(self, name: str) -> str:
        return self.query_one(f"#audit-{name}", textual.widgets.Input).value.strip()

    def _bar(self) -> _Bar:
        return _Bar(
            object=self._input("object"),
            by=self._input("by"),
            types=tuple(self._select("types").selected),
            actions=tuple(self._select("actions").selected),
            levels=tuple(self._select("level").selected),
            follow=self._follow,
        )

    async def _query(self, bar: _Bar) -> dict[str, typing.Any]:
        """The query parameters that a filter bar describes."""
        query: dict[str, typing.Any] = {}
        if bar.types:
            query["object_type"] = list(bar.types)
        if bar.actions:
            query["action"] = list(bar.actions)
        if len(bar.levels) == 1:
            query["level"] = 2 if bar.levels[0] == "warn" else 1
        if bar.by:
            if bar.by.isdigit():
                query["by_identity_id"] = bar.by
            else:
                found = (await self._auth.list_identities(name=bar.by)).identities
                query["by_identity_id"] = str(found[0].id) if found else "-1"
        if bar.object:
            object_type, _, name = bar.object.partition(":")
            query["ref_type"] = object_type
            if name.startswith("#"):
                # `TYPE:#ID` is one object, by id. It is found under every name it has had.
                query["ref_id"] = name[1:]
            elif name:
                query["ref_name"] = name
                query["ref_follow"] = bar.follow
        return query

    async def _reload(self) -> None:
        """Read the first page with the filters of the bar, and keep them for the next pages.

        A reload replaces the one that is running. The answer of the older one is dropped.
        """
        self._generation += 1
        generation = self._generation
        self._loading = True
        bar = self._bar()
        try:
            query = await self._query(bar)
            page = await self._auth.list_audit_log(**query, limit=self._page_size)
        except pfc.exceptions.UI as e:
            if generation == self._generation:
                self._loading = False
                self.notify(str(e), severity="error")
            return
        if generation != self._generation:
            return
        self._loading = False
        self._applied_bar = bar
        self._applied_query = query
        self._new_entries = False
        self._entries = page.entries
        self._cursor = None if page.is_last else page.next_cursor
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
        generation = self._generation
        self._loading = True
        try:
            page = await self._auth.list_audit_log(**self._applied_query, limit=self._page_size, cursor=self._cursor)
        except pfc.exceptions.UI as e:
            if generation == self._generation:
                self._loading = False
                self.notify(str(e), severity="error")
            return
        if generation != self._generation:
            return
        self._loading = False
        self._entries.extend(page.entries)
        self._cursor = None if page.is_last else page.next_cursor
        self._add_rows(page.entries)
        self._update_table_title()

    def _add_rows(self, entries: list[pfc.schemas.AuditLogEntry]) -> None:
        table = self.query_one(textual.widgets.DataTable[str])
        for entry in entries:
            level = "[bold red]WARN[/]" if entry.level == 2 else "INFO"
            at = datetime.datetime.fromtimestamp(entry.at).strftime("%Y-%m-%d %H:%M:%S")
            by = entry.author
            about = ", ".join(f"{r.type}:{r.name or r.id}" for r in entry.refs[:2])
            table.add_row(at, level, entry.type, by, about, key=str(entry.id))

    def _update_table_title(self) -> None:
        """Say which filters the rows were read with, and whether the bar has moved on."""
        more = "+" if self._cursor is not None else ""
        parts = [f"{len(self._entries)}{more} loaded", self._applied_bar.describe()]
        if self._bar() != self._applied_bar:
            parts.append("filters edited, enter to apply")
        if self._new_entries:
            parts.append("new entries, press r")
        self.query_one(textual.widgets.DataTable[str]).border_title = " · ".join(parts)
        self._mark_edited_fields()

    def _mark_edited_fields(self) -> None:
        bar, applied = self._bar(), self._applied_bar
        self.query_one("#audit-object").set_class(bar.object != applied.object, "-edited")
        self.query_one("#audit-by").set_class(bar.by != applied.by, "-edited")
        self._select("types").set_edited(bar.types != applied.types)
        self._select("actions").set_edited(bar.actions != applied.actions)
        self._select("level").set_edited(bar.levels != applied.levels)

    async def _poll(self) -> None:
        if self.app.screen is not self or self._loading:
            return
        generation = self._generation
        try:
            page = await self._auth.list_audit_log(**self._applied_query, limit=1)
        except pfc.exceptions.UI:
            return
        if generation != self._generation:
            return
        if page.entries and (self._newest_id is None or page.entries[0].id > self._newest_id):
            self._new_entries = True
            self._update_table_title()

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
        by = entry.author
        if by:
            local_id = entry.by_identity_id is not None and entry.by_identity_name
            lines.append(f"by    {by}" + (f" (id {entry.by_identity_id})" if local_id else ""))
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
    @textual.on(multi_select.MultiSelect.Submitted)
    async def _on_filter_submitted(self) -> None:
        self.query_one(textual.widgets.DataTable[str]).focus()
        await self._reload()

    @textual.on(textual.widgets.Input.Changed)
    def _on_input_changed(self) -> None:
        self._update_table_title()

    @textual.on(multi_select.MultiSelect.Changed)
    def _on_selection_changed(self, event: multi_select.MultiSelect.Changed) -> None:
        if event.widget.id == "audit-types":
            self._select("actions").set_options(self._action_options())
        self._update_table_title()

    async def action_reload(self) -> None:
        await self._reload()

    async def action_toggle_follow(self) -> None:
        self._follow = not self._follow
        self._update_follow_title()
        await self._reload()

    async def action_clear_filters(self) -> None:
        for name in ("object", "by"):
            self.query_one(f"#audit-{name}", textual.widgets.Input).value = ""
        for name in ("types", "actions", "level"):
            self._select(name).set_selected([])
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
