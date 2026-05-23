import argparse
import asyncio
import datetime
import logging
import os
import os.path
import signal
import socket

from .. import __version__, anet, log
from . import app, control_app, fdstore, systemd

logger = logging.getLogger(__name__)


async def _run(
    conf: app.Config,
    main_sock: anet.socket.Socket,
    ctrl_sock: anet.socket.Socket,
    app_snapshot: app.AppSnapshot | None,
) -> None:
    if app_snapshot is not None:
        main_state = app.AppState.restore(conf, app_snapshot)
    else:
        main_state = app.AppState.create(conf, {})
    main_app = app.create(conf, main_state, main_sock)

    ctrl_state = control_app.AppState(conf=conf, main_state=main_state, main_app=main_app)
    ctrl_app = control_app.create(ctrl_state, ctrl_sock)

    loop = asyncio.get_running_loop()

    async def _sigterm_handler() -> None:
        # Save state to fdstore BEFORE notifying STOPPING=1
        # (fdstore_receiver closes the socket when it sees STOPPING=1)
        ctrl_state.main_app.stop()
        await ctrl_state.main_app.wait_stop()
        ctrl_state.main_state.stop()
        await ctrl_state.main_state.wait_stop()
        await fdstore.save(ctrl_state)
        # Now notify systemd that we're stopping
        systemd.notify("STOPPING=1")
        ctrl_app.stop()

    def sigterm_handler() -> None:
        loop.create_task(_sigterm_handler())  # noqa: RUF006

    loop.add_signal_handler(signal.SIGTERM, sigterm_handler)

    # Wait for both apps to start listening, then notify systemd
    await asyncio.gather(main_app.wait_started(), ctrl_app.wait_started())
    systemd.notify("READY=1")

    await ctrl_app.wait_stop()


def run():
    default_control_socket = os.path.join(os.getenv("XDG_RUNTIME_DIR", "."), "pf-bastion-control.sock")
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--issuer-prefix", help="OIDC issuer url")
    group.add_argument("--dev", action="store_true")
    group.add_argument("--version", action="store_true", help="Print version number and exit")
    parser.add_argument(
        "--domain-suffix", help="Domain suffix for all incoming requests. Default: %(default)s", default="localhost"
    )
    parser.add_argument("-p", "--port", type=int, default=0)
    parser.add_argument("--port-file", default=None)
    parser.add_argument("-d", "--debug", help="Debugging level", action="count", default=0)
    parser.add_argument("--log-filename", default=None)
    parser.add_argument("--control-socket", default=default_control_socket, help="Unix socket path for control API")
    args = parser.parse_args()

    if args.version:
        print(__version__)
        return

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

    # Get FDs from systemd (socket activation + fdstore)
    named = systemd.listen_fds_named()
    logger.debug(f"name sockets={named}")

    if "pf-bastion-main" in named:
        sock = socket.socket(fileno=os.dup(named["pf-bastion-main"]))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", args.port))

    if "pf-bastion-control" in named:
        control_socket = socket.socket(fileno=os.dup(named["pf-bastion-control"]))
    else:
        control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        control_socket.bind(args.control_socket)

    sockname = sock.getsockname()
    host, port = sockname[0], sockname[1]

    if args.port_file is not None:
        with open(args.port_file, "w+") as f:
            f.write(str(port))

    print(f"Starting Bastion on {host}:{port} using FD {sock.fileno()}")

    restored = fdstore.load(named)
    if restored:
        app_snapshot, sockets_snapshot = restored
        anet.sockets.store = anet.sockets.SocketStore.restore(sockets_snapshot)
    else:
        app_snapshot = None

    asyncio.run(
        _run(
            conf=conf,
            main_sock=anet.socket.Socket(sock),
            ctrl_sock=anet.socket.Socket(control_socket),
            app_snapshot=app_snapshot,
        )
    )

    print("Stopped", datetime.datetime.now())
