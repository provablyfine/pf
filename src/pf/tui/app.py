import argparse
import os
import os.path
import sys

import textual.app
import textual.screen
import textual.worker

from .. import client, log
from . import home, relogin, setup

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "pf", "config.json")


class SetupApp(textual.app.App[None]):
    TITLE = "Provably Fine - Setup"

    def __init__(self, initial_screen: textual.screen.Screen[None]) -> None:
        super().__init__()
        self._initial_screen = initial_screen

    def on_mount(self) -> None:
        self.push_screen(self._initial_screen)

    def _handle_exception(self, error: Exception) -> None:
        ui_error: client.exceptions.UI | None = None
        if isinstance(error, client.exceptions.UI):
            ui_error = error
        elif isinstance(error, textual.worker.WorkerFailed) and isinstance(error.error, client.exceptions.UI):
            ui_error = error.error
        if ui_error is not None:
            self.notify(str(ui_error), severity="error")
            return
        super()._handle_exception(error)


class TuiApp(textual.app.App[None]):
    TITLE = "Provably Fine"

    def __init__(self, auth: client.aio.Client) -> None:
        super().__init__()
        self.auth = auth

    def on_mount(self) -> None:
        self.push_screen(home.HomeScreen(self.auth))

    def _handle_exception(self, error: Exception) -> None:
        ui_error: client.exceptions.UI | None = None
        if isinstance(error, client.exceptions.UI):
            ui_error = error
        elif isinstance(error, textual.worker.WorkerFailed) and isinstance(error.error, client.exceptions.UI):
            ui_error = error.error
        if ui_error is not None:
            self.notify(str(ui_error), severity="error")
            return
        super()._handle_exception(error)


def pfat() -> None:
    parser = argparse.ArgumentParser(description="pf admin TUI")
    parser.add_argument("-c", "--config", default=_DEFAULT_CONFIG, help="Configuration file")
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
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)

    if not relogin.has_valid_session(cfg):
        app = SetupApp(relogin.ReloginScreen(cfg, client.Client(cfg), args.config))
        app.run()
        try:
            cfg = client.Config.load(args.config)
        except client.exceptions.UI as e:
            sys.stderr.write(f"{e}\n")
            sys.exit(2)
        if not relogin.has_valid_session(cfg):
            return

    try:
        auth = client.aio.Client(cfg)
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)

    TuiApp(auth).run()
