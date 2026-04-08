import logging
import os

FORMAT = "%(asctime)s:%(levelname)s:%(module)s.%(funcName)s:%(message)s"
DATEFMT = "%H:%M:%S"


def setup(debug: int, log_filename: str) -> None:
    debug = int(os.getenv("PF_LOG_LEVEL", str(debug)))
    if debug == 0:
        return
    match debug:
        case 1:
            level = logging.WARNING
        case 2:
            level = logging.INFO
        case _:
            level = logging.DEBUG
    f = open(log_filename, "a", buffering=1)
    logging.basicConfig(stream=f, level=level, format=FORMAT, datefmt=DATEFMT)


def setup_server(prog: str, level: int, log_filename: str | None = None) -> None:
    """Configure logging for server processes.

    Priority:
    1. log_filename if explicitly set (not None)
    2. PF_LOG_DIRECTORY/<prog>.<pid>.log if PF_LOG_DIRECTORY is set
    3. /dev/stdout
    """
    level = int(os.getenv("PF_LOG_LEVEL", str(level)))
    if level == 0:
        return
    if log_filename is None:
        log_dir = os.environ.get("PF_LOG_DIRECTORY")
        if log_dir:
            log_filename = os.path.join(log_dir, f"{prog}.{os.getpid()}.log")
        else:
            log_filename = "/dev/stdout"
    f = open(log_filename, "a", buffering=1)
    logging.basicConfig(stream=f, level=level, format=FORMAT, datefmt=DATEFMT)


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
        for attr in ("_cmd1", "_cmd2", "_cmd3"):
            val = getattr(args, attr, None)
            if val:
                parts.append(val)
        name = ".".join(parts)
        return os.path.join(log_dir, f"{name}.{os.getpid()}.log")
    return "/dev/stdout"
