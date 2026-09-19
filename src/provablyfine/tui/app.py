import argparse
import asyncio
import enum
import logging
import os
import sys
import typing

import provablyfine_client as pfc
import textual
import textual.app
import textual.containers
import textual.message
import textual.screen
import textual.widgets
import textual.worker

from .. import client, log
from . import base, nav_pane, relogin, sections, setup

_DEFAULT_CONFIG = client.configuration.DEFAULT_CONFIG


class _RestartReason(enum.Enum):
    """Why `TuiApp` exited asking `pfat()` to build a fresh instance, rather
    than really being done.

    Ctx and role switches both work this way. A fresh `TuiApp` starts at the
    section root with a correctly-built `auth`."""

    CTX = "ctx"
    ROLE = "role"


class SetupApp(base.App):
    TITLE = "Provably Fine - Setup"

    def __init__(self, initial_screen: textual.screen.Screen[typing.Any]) -> None:
        super().__init__()
        self._initial_screen = initial_screen

    def on_mount(self) -> None:
        self.push_screen(self._initial_screen)


class _RequestRelogin(textual.message.Message):
    """Posted by `_ReloggingAuth` when a call hits an expired session/key.
    Not awaited: the failing call has already re-raised its original
    exception by the time this gets processed, so whatever triggered it
    (an action, a screen's initial load) simply didn't complete -- the user
    sees an error notification and this relogin prompt, and can retry the
    action once logged back in."""

    def __init__(self, on_result: typing.Callable[[bool, str | None], None]) -> None:
        self.on_result = on_result
        super().__init__()


class _ReloggingAuth(pfc.AsyncSessionClient):
    """Wraps `self.app.auth`: a call that hits an expired session/key posts
    a request to show a relogin prompt, then re-raises the original
    exception -- same as any other error, no transparent retry."""

    def __init__(
        self,
        app: "TuiApp",
        inner: pfc.AsyncSessionClient,
        cfg: client.Config | None,
        config_path: str | None,
    ) -> None:
        super().__init__(inner._inner)  # pyright: ignore[reportPrivateUsage]
        self._app = app
        self._cfg = cfg
        self._config_path = config_path
        self._relogin_pending = False
        # Bumped by every relogin. A call remembers the generation it started
        # in, so a failure caused by the session we just replaced is not
        # mistaken for a failure of the new one.
        self._generation = 0
        # Whether the session of the current generation has been accepted by
        # the server at least once.
        self._verified = False

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        generation = self._generation
        try:
            result = await super()._run(fn)
        except (pfc.exceptions.SessionExpired, pfc.exceptions.KeyExpired):
            self._on_auth_failure(generation)
            raise
        except pfc.exceptions.Forbidden:
            # The server refused the request, but only after accepting the session.
            self._verified = True
            raise
        self._verified = True
        return result

    def _on_auth_failure(self, generation: int) -> None:
        if self._cfg is None or self._config_path is None:
            return
        if generation != self._generation:
            return
        if self._relogin_pending:
            # Several calls can fail against the same expired session. They
            # all share the one relogin already under way.
            return
        if self._generation > 0 and not self._verified:
            self._app.exit(message="Repeated login failures. Restart pfat and check your credentials.")
            return
        self._trigger_relogin()

    def _trigger_relogin(self) -> None:
        if self._relogin_pending:
            return
        self._relogin_pending = True

        def _on_result(success: bool, message: str | None) -> None:
            self._relogin_pending = False
            if not success:
                self._app.exit(message=message)
                return
            assert self._cfg is not None
            self._inner = client.Factory(self._cfg).session()  # pyright: ignore[reportPrivateUsage]
            self._generation += 1
            self._verified = False

        self._app.post_message(_RequestRelogin(_on_result))


class _ContextRenameScreen(base.ModalScreen[str | None]):
    """Single-field "type a new name" modal, modeled on the Input-in-modal
    pattern used by `tag_list.py`'s `_TagCreateScreen` and
    `identity_list.py`'s `_IdentityCreateScreen`: one `base.Input`, submit on
    Enter, cancel on Escape."""

    BINDINGS: typing.ClassVar = [("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    _ContextRenameScreen > VerticalGroup {
        width: 40;
    }
    """

    def __init__(self, old_name: str) -> None:
        super().__init__()
        self._old_name = old_name

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as c:
            c.border_title = f"Rename {self._old_name!r}"
            yield base.Input(value=self._old_name, id="new-name")

    def on_mount(self) -> None:
        self.query_one(base.Input).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.Input.Submitted)
    def _on_submitted(self) -> None:
        value = self.query_one("#new-name", base.Input).value.strip()
        if not value:
            return
        self.dismiss(value)


class _ContextSelectScreen(base.ModalScreen[str | None]):
    """Popup context switcher, bound to a global keybinding on `TuiApp`
    (`SessionPane` is deliberately inert/unfocusable -- see its docstring in
    `nav_pane.py`). Modeled directly on `relogin._RoleSelectScreen`, but
    defined here rather than in `nav_pane.py`: that module is kept free of
    any dependency on `base.py` on purpose, since `base.py` itself imports
    `nav_pane` (see `nav_pane.py`'s own module comment) -- importing `base`
    from `nav_pane` for `ModalScreen` would cycle back.

    Also handles rename ("r") and delete ("d") of the highlighted context,
    persisting immediately -- matching every other delete action in this TUI
    (single keypress, toast afterward, no confirm dialog). Deleting the
    *current* context is refused (same rule as the CLI's `pf ctx delete`):
    `registry.current` can then only ever be `None` (empty registry) or a
    valid key, so there is no stale-current fallback logic to get wrong.
    Adding a context is deliberately not here -- that needs account-key/
    invitation material that's a CLI-native flow (`pf accept`/
    `pfa initialize`), not a TUI one."""

    BINDINGS: typing.ClassVar = [
        ("escape", "cancel", "Cancel"),
        ("r", "rename", "Rename"),
        ("d", "delete", "Delete"),
    ]
    DEFAULT_CSS = """
    _ContextSelectScreen > VerticalGroup {
        width: 40;
    }
    _ContextSelectScreen ListView { height: auto; max-height: 10; }
    """

    def __init__(self, config_path: str) -> None:
        super().__init__()
        self._config_path = config_path
        self._current: str | None = None
        self._names: list[str] = []

    def compose(self) -> textual.app.ComposeResult:
        with textual.containers.VerticalGroup() as c:
            c.border_title = "Switch Context"
            yield textual.widgets.ListView()
            yield textual.widgets.Footer()

    def on_mount(self) -> None:
        self._populate()
        self.query_one(textual.widgets.ListView).focus()

    def _populate(self) -> None:
        # Always show what is on disk right now: other processes may have
        # changed the registry since this popup opened.
        registry = client.configuration.Registry.load(self._config_path)
        self._current = registry.current
        self._names = sorted(registry.contexts)
        lv = self.query_one(textual.widgets.ListView)
        lv.clear()
        for name in self._names:
            marker = "* " if name == self._current else "  "
            lv.append(textual.widgets.ListItem(textual.widgets.Label(f"{marker}{name}")))
        # Unlike constructing ListView(*items) at compose time, .append()
        # after .clear() does not auto-highlight the first row -- without
        # this, "r"/"d" are silent no-ops (_selected_name() sees index=None)
        # until the user presses an arrow key first.
        if self._names:
            lv.index = 0

    def _selected_name(self) -> str | None:
        index = self.query_one(textual.widgets.ListView).index
        if index is None or index >= len(self._names):
            return None
        return self._names[index]

    def action_cancel(self) -> None:
        self.dismiss(None)

    @textual.on(textual.widgets.ListView.Selected)
    def _on_selected(self) -> None:
        name = self._selected_name()
        if name is not None:
            self.dismiss(name)

    @textual.work
    async def action_rename(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        new_name = await self.app.push_screen_wait(_ContextRenameScreen(name))
        if new_name is None or new_name == name:
            return
        try:
            with client.configuration.Registry.transaction(self._config_path) as registry:
                registry.rename(name, new_name)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            self._populate()
            return
        self._populate()
        self.notify(f"Renamed {name!r} to {new_name!r}")

    def action_delete(self) -> None:
        name = self._selected_name()
        if name is None:
            return
        try:
            with client.configuration.Registry.transaction(self._config_path) as registry:
                registry.delete(name)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            self._populate()
            return
        self._populate()
        self.notify(f"Deleted context {name!r}")


class TuiApp(base.App):
    TITLE = "Provably Fine"
    BINDINGS: typing.ClassVar = [
        ("ctrl+t", "switch_context", "Switch context"),
        ("ctrl+r", "switch_role", "Switch role"),
    ]

    def __init__(
        self,
        auth: pfc.AsyncSessionClient,
        *,
        cfg: client.Config | None = None,
        config_path: str | None = None,
    ) -> None:
        super().__init__()
        self._cfg = cfg
        self._config_path = config_path
        self.auth = _ReloggingAuth(self, auth, cfg, config_path)
        self.restart_reason: _RestartReason | None = None

    def on_mount(self) -> None:
        self.current_section_id = sections.SECTIONS[0].id
        self.push_screen(sections.SECTIONS[0].factory(self.auth))
        self._load_whoami()
        self.context_name = self._cfg.context_name if self._cfg is not None and self._cfg.context_name else ""

    def switch_to_section(self, section_id: str) -> None:
        if self.current_section_id == section_id:
            return
        self.current_section_id = section_id
        # `screen_stack[0]` is Textual's own implicit default screen, beneath
        # whatever `on_mount` pushed — never popped, so the target depth is 2
        # (default screen + the section root), not 1.
        while len(self.screen_stack) > 2:
            self.pop_screen()
        self.switch_screen(sections.factory_for(section_id)(self.auth))  # pyright: ignore[reportUnknownMemberType]

    @textual.on(nav_pane.NavPane.Activated)
    def _on_nav_activated(self, event: nav_pane.NavPane.Activated) -> None:
        self.switch_to_section(event.section_id)

    @textual.work
    async def action_switch_context(self) -> None:
        if self._config_path is None or self._cfg is None:
            return
        registry = client.configuration.Registry.load(self._config_path)
        if not registry.contexts:
            self.notify("No contexts. Use 'accept'/'initialize' first.", severity="warning")
            return

        chosen = await self.push_screen_wait(_ContextSelectScreen(self._config_path))
        self._refresh_context_name()
        if chosen is None:
            return
        try:
            with client.configuration.Registry.transaction(self._config_path) as registry:
                changed = registry.use(chosen)
        except pfc.exceptions.UI as e:
            self.notify(str(e), severity="error")
            return
        if not changed:
            return

        # A fresh `TuiApp`, built by pfat()'s loop around _run_tui from the
        # updated registry, starts at the section root with a correctly-built
        # auth.
        self.restart_reason = _RestartReason.CTX
        self.exit()

    def _refresh_context_name(self) -> None:
        """Follow renames made in the switcher (or by another process): the
        context is identified by its directory URL, its name is only a label."""
        assert self._cfg is not None and self._config_path is not None
        registry = client.configuration.Registry.load(self._config_path)
        name = registry.name_for_url(self._cfg.directory_url, prefer=self._cfg.context_name)
        if name is not None:
            self._cfg.context_name = name
            self.context_name = name

    def action_switch_role(self) -> None:
        # role_id is never persisted by pfat() ("cleared at startup ...
        # never persisted", see pfat()), so there's nothing to write here --
        # just ask pfat()'s loop to rebuild with force_relogin=True, which
        # skips the has_valid_session check that would otherwise just reuse
        # the still-valid (but wrong-role) session.
        self.restart_reason = _RestartReason.ROLE
        self.exit()

    @textual.on(_RequestRelogin)
    def _on_request_relogin(self, event: _RequestRelogin) -> None:
        assert self._cfg is not None
        assert self._config_path is not None
        self.push_screen(
            relogin.ReloginScreen(
                self._cfg, client.Client(self._cfg), self._config_path, standalone=False, on_result=event.on_result
            )
        )

    @textual.work
    async def _load_whoami(self) -> None:
        identity = await self.auth.get_self()
        self.identity_name = identity.name
        if identity.active_role is not None:
            self.whoami = f"{identity.name} [{identity.active_role.name}]"
            self.role = identity.active_role.name
        else:
            self.whoami = identity.name
            self.role = ""

    def _handle_exception(self, error: Exception) -> None:
        # `KeyExpired` (client/http_client.py) is deliberately not a
        # `pfc.exceptions.UI` subclass, so base.App's notify-and-continue
        # branch doesn't already cover it the way it does `SessionExpired`.
        unwrapped = error.error if isinstance(error, textual.worker.WorkerFailed) else error
        if isinstance(unwrapped, pfc.exceptions.KeyExpired):
            self.notify(str(unwrapped), severity="error")
            return
        super()._handle_exception(error)


def _has_session(cfg: client.Config) -> bool:
    return (
        cfg.session_key_fingerprint is not None or cfg.session_key_file is not None or cfg.session_key_pem is not None
    )


def _exit_now(code: int) -> typing.NoReturn:
    """Terminate the process immediately, bypassing Python's normal
    interpreter shutdown.

    This is a protection against a potentially rogue thread still running
    and blocking the textual main loop: it allows us to ensure that exiting
    the tui app is always near-instantaneous, even if it is not _clean_.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    logging.shutdown()
    # Bypass `concurrent.futures.thread` atexit handler which waits forever
    # for any stuck thread.
    os._exit(code)


def _run_tui(config_path: str, loop: asyncio.AbstractEventLoop, *, force_relogin: bool) -> _RestartReason | None:
    """Run one `TuiApp` lifetime. Returns the restart reason if it exited
    asking for a ctx/role change, or `None` if it's really done (user quit,
    or a fatal error already printed via `_exit_now`).

    `force_relogin` skips the `has_valid_session` reuse check: a role switch
    needs a fresh login even though the current session is still perfectly
    valid, just bound to the wrong role.
    """
    try:
        cfg = client.Config.load(config_path)
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        _exit_now(2)

    if force_relogin or not relogin.has_valid_session(cfg):
        cfg.role_id = None  # cleared at startup; set in-memory during login, never persisted
        cfg.session_key_fingerprint = None
        cfg.session_key_file = None
        cfg.session_key_pem = None
        SetupApp(relogin.ReloginScreen(cfg, client.Client(cfg), config_path)).run(loop=loop)
        if not _has_session(cfg):
            return None

    try:
        auth = client.Factory(cfg).async_session()
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        _exit_now(2)

    app = TuiApp(auth, cfg=cfg, config_path=config_path)
    app.run(loop=loop)
    return app.restart_reason


def pfat() -> None:
    parser = argparse.ArgumentParser(description="pf admin TUI")
    parser.add_argument("-c", "--config", default=_DEFAULT_CONFIG, help="Configuration file. Default: %(default)s")
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    args = parser.parse_args()

    log.setup(args.debug, log.filename("pfat", args))

    # bypass the default textual loop to avoid
    # waiting forever to cleanup after stuck threads
    loop = asyncio.new_event_loop()

    try:
        registry = client.configuration.Registry.load(args.config)
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        _exit_now(2)

    if not registry.contexts:
        app = SetupApp(setup.SetupChoiceScreen(args.config))
        app.run(loop=loop)
        try:
            registry = client.configuration.Registry.load(args.config)
        except pfc.exceptions.UI as e:
            sys.stderr.write(f"{e}\n")
            _exit_now(2)
        if not registry.contexts:
            _exit_now(0)

    force_relogin = False
    while True:
        reason = _run_tui(args.config, loop, force_relogin=force_relogin)
        if reason is None:
            break
        force_relogin = reason is _RestartReason.ROLE
    _exit_now(0)
