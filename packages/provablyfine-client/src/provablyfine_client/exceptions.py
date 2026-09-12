class UI(Exception):
    """A user-facing error: its message is meant to reach the end user
    unmodified, displayed by a top-level UI layer.

    It must propagate to a top-level handler, which display `str(e)` as-is.
    For example:

    - the CLI entrypoint, `provablyfine.cli.common.do_main` (binaries `pf`
      and `pfa`)
    - the TUI entrypoint, `provablyfine.tui.app.pfat`, for failures before
      the app runs
    - the TUI app, `provablyfine.tui.base.App._handle_exception`, which
      worker failures reach wrapped in `textual.worker.WorkerFailed`

    The only other legitimate catches clean up or recover, then re-raise the
    original exception so the final failure still reaches a top-level
    handler.
    """


class Forbidden(UI):
    """The server refused the request (HTTP 403); see `UI`."""


class SessionExpired(UI):
    """The server refused the session credentials (HTTP 401); see `UI`. The
    TUI also catches this subclass to trigger an interactive relogin."""


class KeyExpired(Exception):
    """The account or session key has expired. Not a `UI` subclass: the CLI
    top-level handler rewrites it into login guidance."""

    def __init__(self, key_type: str):
        self.key_type = key_type
