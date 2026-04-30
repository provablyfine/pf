import argparse
import asyncio
import datetime
import signal
import socket
import types

from . import app


def run():
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
    application = app.create(conf, sock)

    print(f"Starting Bastion on {host}:{port} using FD {sock.fileno()}")

    def handler(signum: int, frame: types.FrameType | None) -> None:
        application.stop()

    signal.signal(signal.SIGTERM, handler)
    asyncio.run(application.run())

    print("Stopped", datetime.datetime.now())
