import argparse
import asyncio
import logging
import os
import os.path
import sys
import typing

import provablyfine_client as pfc
import textual
import textual.message
import textual.screen
import textual.worker

from .. import client, log
from . import base, nav_pane, relogin, sections, setup

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "provablyfine", "config.json")


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

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        try:
            return await super()._run(fn)
        except (pfc.exceptions.SessionExpired, pfc.exceptions.KeyExpired):
            if self._cfg is not None and self._config_path is not None:
                self._trigger_relogin()
            raise

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

        self._app.post_message(_RequestRelogin(_on_result))


class TuiApp(base.App):
    TITLE = "Provably Fine"

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

    def on_mount(self) -> None:
        self.current_section_id = sections.SECTIONS[0].id
        self.push_screen(sections.SECTIONS[0].factory(self.auth))
        self._load_whoami()
        self.tenant_name = self._cfg.tenant_name if self._cfg is not None else ""

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

    if not os.path.exists(args.config):
        app = SetupApp(setup.SetupChoiceScreen(args.config))
        app.run(loop=loop)
        if not os.path.exists(args.config):
            _exit_now(0)

    try:
        cfg = client.Config.load(args.config)
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        _exit_now(2)

    cfg.role_id = None  # cleared at startup; set in-memory during login, never persisted
    cfg.session_key_fingerprint = None
    cfg.session_key_file = None
    cfg.session_key_pem = None
    SetupApp(relogin.ReloginScreen(cfg, client.Client(cfg), args.config)).run(loop=loop)
    if not _has_session(cfg):
        _exit_now(0)

    try:
        auth = client.Factory(cfg).async_session()
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        _exit_now(2)

    TuiApp(auth, cfg=cfg, config_path=args.config).run(loop=loop)
    _exit_now(0)
