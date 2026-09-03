import logging
import sysconfig
import traceback
import types

import uvicorn.logging

from .. import log

_EXCLUDED = (
    "/site-packages/uvicorn/",
    "/site-packages/starlette/",
    "/site-packages/fastapi/",
    "/site-packages/anyio/",
    "/asyncio/",
    "/concurrent/futures/",
)

# The middleware stack unwinds through contextlib and friends, so filtering the
# frameworks alone still leaves a wall of stdlib frames behind.  When installed
# from a package, our own code lives under site-packages, which in turn lives
# under the stdlib prefix -- hence the second half of the test.
_STDLIB = sysconfig.get_paths()["stdlib"]


def _app_frame(frame: traceback.FrameSummary) -> bool:
    if any(seg in frame.filename for seg in _EXCLUDED):
        return False
    if "call_next" in (frame.line or ""):
        return False
    if frame.filename.startswith(_STDLIB) and "site-packages" not in frame.filename:
        return False
    return True


def _filter(exc: traceback.TracebackException) -> None:
    exc.stack = traceback.StackSummary.from_list([f for f in exc.stack if _app_frame(f)])
    if exc.__cause__ is not None:
        _filter(exc.__cause__)
    if exc.__context__ is not None:
        _filter(exc.__context__)
    if exc.exceptions is not None:
        for sub in exc.exceptions:
            _filter(sub)


class SuppressASGIException(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return "Exception in ASGI application" not in record.getMessage()


class AppFormatter(uvicorn.logging.DefaultFormatter):
    def formatException(  # type: ignore[override]
        self,
        ei: tuple[type[BaseException], BaseException, types.TracebackType | None],
    ) -> str:
        exc_type, exc_value, exc_tb = ei
        exc = traceback.TracebackException(exc_type, exc_value, exc_tb)
        _filter(exc)
        return "".join(exc.format()).rstrip()


def log_config(pf_log_filename: str | None = None) -> dict[str, object]:
    """Return a `logging.config.dictConfig` mapping for the api server.

    Identical to uvicorn's own default configuration except that exceptions are
    rendered by `AppFormatter`, which drops the framework frames that otherwise
    bury the handful of application frames that actually matter.

    Pass to uvicorn with `--log-config`.  The result is JSON-serializable so it
    can be written to a file first.  When `pf_log_filename` is given, the `pf`
    loggers are additionally written there in the same format as every other
    `pf` process.
    """
    handlers: dict[str, object] = {
        "default": {"formatter": "default", "class": "logging.StreamHandler", "stream": "ext://sys.stderr"},
        "access": {"formatter": "access", "class": "logging.StreamHandler", "stream": "ext://sys.stdout"},
    }
    config: dict[str, object] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": f"{AppFormatter.__module__}.{AppFormatter.__qualname__}",
                "fmt": "%(levelprefix)s %(message)s",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
            "pf": {"format": log.FORMAT, "datefmt": log.DATEFMT},
        },
        "handlers": handlers,
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"level": "INFO"},
            "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
        },
    }
    if pf_log_filename is not None:
        handlers["pf"] = {
            "class": "logging.FileHandler",
            "filename": pf_log_filename,
            "mode": "a",
            "formatter": "pf",
        }
        config["root"] = {"handlers": ["pf"], "level": "DEBUG"}
    return config
