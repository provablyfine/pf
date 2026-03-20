import argparse
import datetime
import socket
import urllib.parse

import uvicorn

from . import app, config


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="pf-server.yaml")
    parser.add_argument("-p", "--port", type=int, default=0)
    parser.add_argument("--port-file", default=None)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", args.port))

    host, port = sock.getsockname()

    if args.port_file is not None:
        with open(args.port_file, "w+") as f:
            f.write(str(port))

    conf = config.Config.load(args.config)
    base_url = urllib.parse.urlparse(conf.base_url)
    base_url = base_url._replace(netloc=f"{host}:{port}")
    conf.base_url = urllib.parse.urlunparse(base_url)

    application = app.create(conf)

    print(f"Starting Uvicorn on {host}:{port} using FD {sock.fileno()}")

    try:
        uvicorn.run(application, fd=sock.fileno(), log_level="info")
    except SystemExit:
        pass

    print("Stopped", datetime.datetime.now())
