import argparse
import os
import os.path
import sys

import provablyfine_client as pfc
import textual
import textual.worker

from .. import client, log
from . import base, home, relogin, setup

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
        self.push_screen(home.HomeScreen(self.auth))
        self._load_whoami()

    @textual.work
    async def _load_whoami(self) -> None:
        identity = await self.auth.get_self()
        self.whoami = identity.name

    def _handle_exception(self, error: Exception) -> None:
        if self._cfg is not None and self._config_path is not None:
            expired = isinstance(error, pfc.exceptions.SessionExpired) or (
                isinstance(error, textual.worker.WorkerFailed)
                and isinstance(error.error, pfc.exceptions.SessionExpired)
            )
            if expired:
                self.push_screen(
                    relogin.ReloginScreen(self._cfg, client.Client(self._cfg), self._config_path),
                    callback=self._on_relogin,
                )
                return
        super()._handle_exception(error)

    def _on_relogin(self, _: None) -> None:
        assert self._cfg is not None
        self.auth = client.Factory(self._cfg).async_session()
        self.query_one(home.HomeScreen).refresh_auth(self.auth)


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
