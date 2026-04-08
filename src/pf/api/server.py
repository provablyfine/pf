import argparse
import datetime
import signal
import socket
import urllib.parse

import uvicorn

from . import app, config


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="pf-server.yaml")
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

    conf = config.Config.load(args.config)
    conf.log_filename = args.log_filename
    base_url = urllib.parse.urlparse(conf.base_url)
    base_url = base_url._replace(netloc=f"{host}:{port}")
    conf.base_url = urllib.parse.urlunparse(base_url)

    application = app.create(conf)

    print(f"Starting Uvicorn on {host}:{port} using FD {sock.fileno()}")

    def handler(signum, frame):
        # We do nothing on purpose: this allows uvicorn.run to return
        # gracefully and this all other handlers run naturally which
        # specifically is good for coverage tracking
        # Now, you might want to know why doing nothing here (which
        # consumes the signal) would result in uvicorn.run returning.
        # This happens because uvicorn calls signal.set_wakeup_fd so
        # that the python C code wakes up the file descriptor whenever
        # a signal is received, regardless of what the corresponding
        # python handler did.
        # We do nothing, so, the asyncio main loop runs, uvicorn eventually
        # reads from this file descriptor, sees that a SIGTERM was received
        # and just returns from the run() function below.
        #
        # OMG. I wish I did not know any of this.
        pass

    signal.signal(signal.SIGTERM, handler)
    try:
        uvicorn.run(application, fd=sock.fileno(), log_level="info")
    except SystemExit:
        pass

    print("Stopped", datetime.datetime.now())
