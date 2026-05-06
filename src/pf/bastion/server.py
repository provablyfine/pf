import argparse
import asyncio
import datetime
import logging
import os
import os.path
import signal
import socket

from .. import anet
from . import app, control_app, http

logger = logging.getLogger(__name__)


async def _run(
    main_app: http.Application[app.AppState],
    ctrl_app: http.Application[control_app.AppState],
) -> None:
    app_holder = [main_app, ctrl_app]

    def sigterm_handler() -> None:
        for a in app_holder:
            a.stop()

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, sigterm_handler)
    main_task = asyncio.create_task(main_app.run())
    ctrl_task = asyncio.create_task(ctrl_app.run())

    await main_task
    await ctrl_task


def run():
    default_control_socket = os.path.join(os.getenv("XDG_RUNTIME_DIR", "."), "pf-bastion-control.sock")
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--issuer-prefix", help="OIDC issuer url")
    group.add_argument("--dev", action="store_true")
    parser.add_argument(
        "--domain-suffix", help="Domain suffix for all incoming requests. Default: %(default)s", default="localhost"
    )
    parser.add_argument("-p", "--port", type=int, default=0)
    parser.add_argument("--port-file", default=None)
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", default=None)
    parser.add_argument("--control-socket", default=default_control_socket, help="Unix socket path for control API")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))

    host, port = sock.getsockname()

    if args.port_file is not None:
        with open(args.port_file, "w+") as f:
            f.write(str(port))

    if args.dev:
        conf = app.Config(
            domain_suffix=args.domain_suffix,
            dev_tenant_id=1,
            dev_name="hello",
            issuer_prefix=None,
            log_level=args.debug,
            log_filename=args.log_filename,
        )
    else:
        conf = app.Config(
            domain_suffix=args.domain_suffix,
            dev_tenant_id=None,
            dev_name=None,
            issuer_prefix=args.issuer_prefix,
            log_level=args.debug,
            log_filename=args.log_filename,
        )

    print(f"Starting Bastion on {host}:{port} using FD {sock.fileno()}")

    control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control_socket.bind(args.control_socket)

    main_state = app.AppState.create(conf, {})
    main_app = app.create(conf, main_state, anet.socket.Socket(sock))
    ctrl_state = control_app.AppState(main_state)
    ctrl_app = control_app.create(ctrl_state, anet.socket.Socket(control_socket))
    asyncio.run(_run(main_app, ctrl_app))

    print("Stopped", datetime.datetime.now())
