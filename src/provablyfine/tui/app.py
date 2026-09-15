import argparse
import functools
import os
import os.path
import sys

import provablyfine_client as pfc
import textual
import textual.worker

from .. import client, log
from . import base, nav_pane, relogin, sections, setup

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "provablyfine", "config.json")


class SetupApp(base.App):
    TITLE = "Provably Fine - Setup"

    def __init__(self, initial_screen: base.Screen) -> None:
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

    def switch_to_section(self, section_id: str, force: bool) -> None:
        if self.current_section_id == section_id and not force:
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
        self.switch_to_section(event.section_id, force=False)

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
                    relogin.ReloginScreen(self._cfg, client.Client(self._cfg), self._config_path, standalone=False),
                    callback=functools.partial(self._on_relogin, self.current_section_id),
                )
                return
        super()._handle_exception(error)

    def _on_relogin(self, section_id: str | None, _: None) -> None:
        assert self._cfg is not None
        # Every section/view screen and grant-edit widget reads `self.app.auth`
        # live rather than caching it, so a plain reassignment here is enough
        # to reach all of them -- including the ones popped back onto (and
        # thus momentarily resumed) below.
        self.auth = client.Factory(self._cfg).async_session()
        if section_id is not None:
            self.switch_to_section(section_id, force=True)


def _has_session(cfg: client.Config) -> bool:
    return (
        cfg.session_key_fingerprint is not None or cfg.session_key_file is not None or cfg.session_key_pem is not None
    )


def pfat() -> None:
    parser = argparse.ArgumentParser(description="pf admin TUI")
    parser.add_argument("-c", "--config", default=_DEFAULT_CONFIG, help="Configuration file. Default: %(default)s")
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", help="Filename where logs will be written", default=None)
    args = parser.parse_args()

    log.setup(args.debug, log.filename("pfat", args))

    if not os.path.exists(args.config):
        app = SetupApp(setup.SetupChoiceScreen(args.config))
        app.run()
        if not os.path.exists(args.config):
            return

    try:
        cfg = client.Config.load(args.config)
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)

    cfg.role_id = None  # cleared at startup; set in-memory during login, never persisted
    cfg.session_key_fingerprint = None
    cfg.session_key_file = None
    cfg.session_key_pem = None
    SetupApp(relogin.ReloginScreen(cfg, client.Client(cfg), args.config)).run()
    if not _has_session(cfg):
        return

    try:
        auth = client.Factory(cfg).async_session()
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)

    TuiApp(auth, cfg=cfg, config_path=args.config).run()
