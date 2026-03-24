import argparse
import os.path
import sys

import textual.app
import textual.worker

from .. import client
from . import async_client, role_list

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "pf", "config.json")


class TuiApp(textual.app.App[None]):
    TITLE = "Provably Fine"

    def __init__(self, auth):
        super().__init__()
        self.auth = auth

    def on_mount(self) -> None:
        self.push_screen(role_list.RoleListScreen(self.auth))

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
    args = parser.parse_args()

    try:
        cfg = client.Config.load(args.config)
        api = client.Client(cfg)
        auth = async_client.AsyncClient(api.session_auth(cfg.session_key))
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)

    TuiApp(auth).run()
