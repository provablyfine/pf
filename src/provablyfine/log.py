from __future__ import annotations

import functools
import inspect
import logging
import os
import sys
import types
import typing

FORMAT = "%(asctime)s:%(levelname)s:%(module)s.%(funcName)s:%(message)s"
DATEFMT = "%H:%M:%S"

TraceFunc = typing.Callable[[types.FrameType, str, typing.Any], "TraceFunc | None"]

logger = logging.getLogger(__name__)


def trace_lines(func: typing.Callable[..., typing.Any]) -> typing.Callable[..., typing.Any]:
    """
    Enable debug logging for each single line in a function.
    Functions called by this function are not traced.
    """

    def get_tracer(initial_frame: types.FrameType) -> TraceFunc:
        def tracer(frame: types.FrameType, event: str, arg: typing.Any) -> TraceFunc | None:
            if frame is not initial_frame:
                return None
            if event == "line":
                module_name = frame.f_globals.get("__name__", "<unknown>")
                qualname = getattr(frame.f_code, "co_qualname", frame.f_code.co_name)
                logger.debug(f"Trace {module_name}.{qualname}:{frame.f_lineno}")
            return tracer

        return tracer

    def get_initial_tracer() -> TraceFunc:
        # We need an initial_tracer to capture the frame of the function
        activated = False

        def initial_tracer(frame: types.FrameType, event: str, arg: typing.Any) -> TraceFunc | None:
            nonlocal activated
            if event == "call" and not activated:
                activated = True
                return get_tracer(frame)
            return None

        return initial_tracer

    @functools.wraps(func)
    async def async_wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        sys.settrace(get_initial_tracer())
        try:
            return await func(*args, **kwargs)
        finally:
            sys.settrace(None)

    @functools.wraps(func)
    def sync_wrapper(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        sys.settrace(get_initial_tracer())
        try:
            return func(*args, **kwargs)
        finally:
            sys.settrace(None)

    # switch implementation for async vs normal functions
    return async_wrapper if inspect.iscoroutinefunction(func) else sync_wrapper


def setup(debug: int, log_filename: str) -> None:
    log_level = os.getenv("PF_LOG_LEVEL")
    match log_level:
        case "DEBUG":
            debug = 3
        case "INFO":
            debug = 2
        case "WARNING":
            debug = 1
        case None:
            pass
        case _:
            try:
                debug = int(log_level)
            except ValueError:
                pass
    if debug == 0:
        return
    match debug:
        case 1:
            level = logging.WARNING
        case 2:
            level = logging.INFO
        case _:
            level = logging.DEBUG
    try:
        f = open(log_filename, "a", buffering=1)
    except Exception:
        f = sys.stdout
    logging.basicConfig(stream=f, level=level, format=FORMAT, datefmt=DATEFMT)


def setup_server(prog: str, level: int, log_filename: str | None = None) -> None:
    """Configure logging for server processes.

    Priority:
    1. log_filename if explicitly set (not None)
    2. PF_LOG_DIRECTORY/<prog>.<pid>.log if PF_LOG_DIRECTORY is set
    3. /dev/stdout
    """
    if log_filename is None:
        log_dir = os.environ.get("PF_LOG_DIRECTORY")
        if log_dir:
            log_filename = os.path.join(log_dir, f"{prog}.{os.getpid()}.log")
        else:
            log_filename = "/dev/stdout"
    setup(level, log_filename)


def filename(prog: str, args: object) -> str:
    """Return the log file path for this process.

    Priority:
    1. args.log_filename if explicitly set (not None)
    2. PF_LOG_DIRECTORY/<prog>.<subcommands>.<pid>.log if PF_LOG_DIRECTORY is set
    3. /dev/stdout
    """
    explicit = getattr(args, "log_filename", None)
    if explicit is not None:
        return explicit
    log_dir = os.environ.get("PF_LOG_DIRECTORY")
    if log_dir:
        parts = [prog]
        for attr in ("command", "subcommand", "subsubcommand"):
            val = getattr(args, attr, None)
            if val:
                parts.append(val)
        name = ".".join(parts)
        return os.path.join(log_dir, f"{name}.{os.getpid()}.log")
    return "/dev/stdout"
