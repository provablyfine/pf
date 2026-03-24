import argparse
import os.path
import sys

import textual.app


from .. import client
from . import grant_edit

_DEFAULT_CONFIG = os.path.join(os.path.expanduser("~"), ".config", "pf", "config.json")


class TuiApp(textual.app.App[None]):
    TITLE = "Provably Fine"

    def __init__(self, auth):
        super().__init__()
        self.auth = auth

    def on_mount(self) -> None:
        grant = {
            "type": "role",
            "filter": {"name": None},
            "permission": {
                "create": False,
                "read": False,
                "update": {
                    "name": False,
                    "description": False,
                    "grant_list": False,
                    "member_list": False,
                },
                "delete": False,
            },
        }
        self.push_screen(grant_edit.GrantEditScreen(grant))


def pfat() -> None:
    parser = argparse.ArgumentParser(description="pf admin TUI")
    parser.add_argument("-c", "--config", default=_DEFAULT_CONFIG, help="Configuration file")
    args = parser.parse_args()

    try:
        cfg = client.Config.load(args.config)
        api = client.Client(cfg)
        auth = api.session_auth(cfg.session_key)
    except client.exceptions.UI as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)

    TuiApp(auth).run()
