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


class _ReloginFailed(Exception):
    """Raised by `_ReloggingAuth._relogin` when the interactive relogin it
    triggered didn't produce a working session (cancelled, failed outright,
    or the fresh session broke again immediately on retry). Deliberately not
    a `pfc.exceptions.UI` -- `TuiApp._handle_exception` treats this as fatal
    (exit the app) rather than notify-and-continue the way an ordinary `UI`
    error does: there is no partial-recovery path where the TUI keeps
    running with a session it couldn't fix.

    Must be raised (not returned/swallowed) from inside the same call chain
    that's awaiting it, rather than the app being told to exit directly from
    a screen's dismiss callback: that call chain is nested arbitrarily deep
    inside the app's own message-processing loop (e.g. a freshly-navigated
    screen's own `on_mount`, itself inside `switch_screen`'s mount-await),
    which is the *same* loop `App.exit()` needs to be free in order to act
    on. Only once this propagates as an ordinary exception back up to that
    loop's own top-level dispatch (where `_handle_exception` is actually
    invoked) is it safe to call `exit()`."""


class _ReloggingAuth(pfc.AsyncSessionClient):
    """Wraps `self.app.auth` so a `SessionExpired`/`KeyExpired` failure from
    any of `AsyncSessionClient`'s 33 methods -- every one of which already
    funnels through `_run` -- triggers an interactive relogin and a single
    transparent retry, without the failing screen ever seeing the exception.
    Subclassing (rather than composing) means every method is inherited
    as-is; only `_run` needs overriding."""

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
        self._generation = 0
        self._relogin_task: asyncio.Task[None] | None = None

    async def _run(self, fn: typing.Callable[[], typing.Any]) -> typing.Any:
        try:
            return await super()._run(fn)
        except (pfc.exceptions.SessionExpired, pfc.exceptions.KeyExpired):
            if self._cfg is None or self._config_path is None:
                raise
            observed = self._generation
            await self._relogin(observed)  # raises _ReloginFailed if this didn't work
            try:
                return await super()._run(fn)  # retry exactly once
            except (pfc.exceptions.SessionExpired, pfc.exceptions.KeyExpired) as e:
                # The relogin reported success, but the fresh session is
                # already broken too -- equally fatal, not a third path
                # where the TUI keeps running regardless.
                raise _ReloginFailed(f"Session still broken after relogin: {e}") from e

    async def _relogin(self, observed_generation: int) -> None:
        if self._generation != observed_generation:
            return  # someone else already relogged in since we last checked
        # Single-flight: every concurrent caller that observed the same
        # (still-current) generation awaits the *same* task rather than
        # each pushing its own `ReloginScreen`. A generation bump only
        # happens on success, so a bare generation check alone isn't enough
        # to prevent duplicates -- after a failure, every waiter would still
        # see the same (unchanged) generation and, without this, each push
        # its own redundant screen. Sharing one task means they all instead
        # share its one outcome, success or `_ReloginFailed`. Safe without
        # an explicit lock: nothing here awaits between reading
        # `self._relogin_task` and (re)assigning it, so two calls can't
        # race to create two tasks.
        task = self._relogin_task
        if task is None or task.done():
            task = asyncio.create_task(self._do_relogin())
            self._relogin_task = task
        await task

    async def _do_relogin(self) -> None:
        assert self._cfg is not None
        assert self._config_path is not None
        loop = asyncio.get_running_loop()
        future: asyncio.Future[None] = loop.create_future()

        def _on_result(success: bool, message: str | None) -> None:
            if future.done():
                return
            if not success:
                future.set_exception(_ReloginFailed(message or "Relogin cancelled"))
                return
            assert self._cfg is not None
            self._inner = client.Factory(self._cfg).session()  # pyright: ignore[reportPrivateUsage]
            self._generation += 1
            future.set_result(None)

        self._app.push_screen(
            relogin.ReloginScreen(
                self._cfg, client.Client(self._cfg), self._config_path, standalone=False, on_result=_on_result
            )
        )
        await future


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
        unwrapped = error.error if isinstance(error, textual.worker.WorkerFailed) else error
        if isinstance(unwrapped, _ReloginFailed):
            self.exit(message=str(unwrapped) if str(unwrapped) else None)
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
