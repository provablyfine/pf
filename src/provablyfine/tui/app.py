import argparse
import os
import os.path
import sys

import provablyfine_client as pfc
import textual.screen

from .. import client, log
from . import base, home, relogin, setup

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "provablyfine", "config.json")


class SetupApp(base.App):
    TITLE = "Provably Fine - Setup"

    def __init__(self, initial_screen: textual.screen.Screen[None]) -> None:
        super().__init__()
        self._initial_screen = initial_screen

    def on_mount(self) -> None:
        self.push_screen(self._initial_screen)


class TuiApp(base.App):
    TITLE = "Provably Fine"

    def __init__(self, auth: pfc.AsyncSessionClient) -> None:
        super().__init__()
        self.auth = auth

    def on_mount(self) -> None:
        self.push_screen(home.HomeScreen(self.auth))


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

    if not relogin.has_valid_session(cfg):
        app = SetupApp(relogin.ReloginScreen(cfg, client.Client(cfg), args.config))
        app.run()
        try:
            cfg = client.Config.load(args.config)
        except pfc.exceptions.UI as e:
            sys.stderr.write(f"{e}\n")
            sys.exit(2)
        if not relogin.has_valid_session(cfg):
            return

    try:
        auth = client.Factory(cfg).async_session()
    except pfc.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)

    TuiApp(auth).run()
