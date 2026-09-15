import argparse
import asyncio
import logging
import os
import os.path
import sys
import typing

import provablyfine_client as pfc
import textual
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
        self.auth = auth

    def on_mount(self) -> None:
        self.current_section_id = sections.SECTIONS[0].id
        self.push_screen(sections.SECTIONS[0].factory())
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
        self.switch_screen(sections.factory_for(section_id)())  # pyright: ignore[reportUnknownMemberType]

    @textual.on(nav_pane.NavPane.Activated)
    def _on_nav_activated(self, event: nav_pane.NavPane.Activated) -> None:
        self.switch_to_section(event.section_id)

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
        if self._cfg is not None and self._config_path is not None:
            # Unwrapped only for this classification check -- the fallback
            # below still passes the original `error` (`WorkerFailed` and
            # all) to `super()`, which does its own unwrapping and expects
            # the wrapper for its crash report.
            unwrapped = error.error if isinstance(error, textual.worker.WorkerFailed) else error
            # `SessionExpired` (a `UI` subclass) is the server *rejecting*
            # the session, discovered on a request's 401 response.
            # `KeyExpired` is the client unable to reach the signing oracle
            expired = isinstance(unwrapped, (pfc.exceptions.SessionExpired, pfc.exceptions.KeyExpired))
            if expired:
                # A single session expiry routinely surfaces as more than one
                # failure at once. The first one is enough.
                if any(isinstance(s, relogin.ReloginScreen) for s in self.screen_stack):
                    return
                self.push_screen(
                    relogin.ReloginScreen(self._cfg, client.Client(self._cfg), self._config_path, standalone=False)
                )
                return
        super()._handle_exception(error)


def _has_session(cfg: client.Config) -> bool:
    return (
        cfg.session_key_fingerprint is not None or cfg.session_key_file is not None or cfg.session_key_pem is not None
    )


def _exit_now(code: int) -> typing.NoReturn:
    """Terminate the process immediately, bypassing Python's normal
    interpreter shutdown.

    By the time this runs, a `.run()` call has already returned, so
    Textual's own teardown is done: screen closed, terminal restored.
    Nothing about the *app* is left half-finished. The problem is
    elsewhere: every signed API call (`AsyncSessionClient._run`) and every
    `ReloginScreen._login` attempt runs in a real OS thread via
    `asyncio.to_thread`/`@textual.work(thread=True)`, and
    `concurrent.futures.thread` registers an `atexit` hook that joins every
    such thread -- across the whole process, not just this app's -- before
    the interpreter is allowed to actually exit. Cancelling the asyncio
    task wrapping one of those (which is all quitting normally does) does
    not stop the underlying thread; a blocked `socket.recv()` keeps
    blocking regardless.

    Some of those threads can legitimately run for as long as a human
    takes to respond: signing against a confirmation-required real
    ssh-agent (see `client/http_client.py`'s `account_key_signer`) has no
    timeout, by design. So no timeout on any individual operation can
    guarantee quitting is instant -- only skipping the wait entirely can.
    Any such background work is simply abandoned mid-operation, with no
    chance to fail gracefully into its own exception handling; that's the
    trade this makes.

    This alone isn't enough, though: `App.run()` without an explicit `loop`
    drives the app via `asyncio.run()`, whose *own* cleanup (`Runner.close()`)
    calls `loop.shutdown_default_executor(THREAD_JOIN_TIMEOUT)` -- a 300
    *second* wait for the same stuck thread -- before `.run()` can even
    return to let this function run at all. `pfat()` sidesteps that by
    passing its own `loop=` to every `.run()` call, which makes Textual take
    the `loop.run_until_complete(...)` path instead of `asyncio.run(...)`;
    `run_until_complete` returns as soon as the app itself finishes, with no
    such wait. Verified empirically: a real `@textual.work(thread=True)`
    worker stuck in a `recv()` with no timeout, `App.run(loop=...)` still
    returns in ~0s once `self.exit()` is called.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    logging.shutdown()
    os._exit(code)


def pfat() -> None:
    parser = argparse.ArgumentParser(description="pf admin TUI")
    parser.add_argument("-c", "--config", default=_DEFAULT_CONFIG, help="Configuration file. Default: %(default)s")
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    args = parser.parse_args()

    log.setup(args.debug, log.filename("pfat", args))

    # Passed explicitly to every `.run()` below -- see `_exit_now`'s
    # docstring for why: it's what lets a stuck background thread not
    # block quitting.
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
