import argparse
import datetime
import socket
import urllib.parse

import gunicorn.app.base

from . import app, config


class StandaloneApplication(gunicorn.app.base.BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", default="pf-server.yaml")
    parser.add_argument("-p", "--port", type=int, default=0)
    parser.add_argument("--port-file", default=None)
    parser.add_argument("-t", "--timeout", type=int, default=1)
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

    options = {
        "bind": f"fd://{sock.fileno()}",
        "workers": 1,
        "timeout": args.timeout,
        "graceful_timeout": 1,
        # --- Logging Configuration ---
        "accesslog": "-",
        "errorlog": "-",
        "access_log_format": "%(t)s %(m)s %(U)s status=%(s)s bytes=%(b)s delay=%(M)sms",
        "loglevel": "info",
    }

    print(f"Starting Gunicorn on {host}:{port} using FD {sock.fileno()}")

    try:
        StandaloneApplication(application, options).run()
    except SystemExit:
        pass

    print("Stopped", datetime.datetime.now())
