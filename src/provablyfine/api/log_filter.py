import logging
import traceback
import types

import uvicorn.logging

_EXCLUDED = (
    "/site-packages/uvicorn/",
    "/site-packages/starlette/",
    "/site-packages/fastapi/",
    "/site-packages/anyio/",
    "/asyncio/",
    "/concurrent/futures/",
)


def _app_frame(frame: traceback.FrameSummary) -> bool:
    if any(seg in frame.filename for seg in _EXCLUDED):
        return False
    if "call_next" in (frame.line or ""):
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
