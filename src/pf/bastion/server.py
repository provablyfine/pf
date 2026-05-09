import argparse
import asyncio
import datetime
import logging
import os
import os.path
import signal
import socket

from .. import anet, log
from . import app, control_app

logger = logging.getLogger(__name__)


async def _run(
    conf: app.Config,
    main_sock: anet.socket.Socket,
    ctrl_sock: anet.socket.Socket,
) -> None:
    main_state = app.AppState.create(conf, {})
    main_app = app.create(conf, main_state, main_sock)

    ctrl_state = control_app.AppState(conf=conf, main_state=main_state, main_app=main_app)
    ctrl_app = control_app.create(ctrl_state, ctrl_sock)

    def sigterm_handler() -> None:
        ctrl_app.stop()

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, sigterm_handler)

    await ctrl_app.wait_stop()


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
    log.setup_server("pf-bastion", conf.log_level, conf.log_filename)

    print(f"Starting Bastion on {host}:{port} using FD {sock.fileno()}")

    control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control_socket.bind(args.control_socket)

    asyncio.run(_run(
        conf=conf,
        main_sock=anet.socket.Socket(sock),
        ctrl_sock=anet.socket.Socket(control_socket),
    ))

    print("Stopped", datetime.datetime.now())
