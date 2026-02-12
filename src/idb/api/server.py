from __future__ import annotations
import argparse
import urllib.parse
import wsgiref.simple_server

from . import config
from . import app


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='idb.yaml')
    parser.add_argument('-p', '--port', type=int, default=None)
    parser.add_argument('--port-file', default=None)
    args = parser.parse_args()
    server = wsgiref.simple_server.WSGIServer(
        ('127.0.0.1', 0 if args.port is None else args.port),
        wsgiref.simple_server.WSGIRequestHandler
    )
    if args.port_file is not None:
        with open(args.port_file, 'w+') as f:
            f.write(f'{server.server_address[1]}')
    conf = config.Config.load(args.config)
    base_url = urllib.parse.urlparse(conf.base_url)
    base_url = base_url._replace(netloc=f'{server.server_address[0]}:{server.server_address[1]}')
    conf.base_url = urllib.parse.urlunparse(base_url)
    application = app.create(conf)
    server.set_app(application)
    server.serve_forever()
