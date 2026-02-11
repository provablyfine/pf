import time
import logging
import sys

import json

from .. import wa
from .. import jwk

from . import config
from . import middleware
from . import endpoint
from .context import ctx


def create(conf):
    match conf.log_level:
        case 'DEBUG':
            level = logging.DEBUG
        case 'INFO':
            level = logging.INFO
        case 'WARNING':
            level = logging.WARN
        case 'ERROR':
            level = logging.ERROR
    logging.basicConfig(stream=sys.stdout, level=level)
    middlewares = [
        middleware.KekContext(),
    ]
    app = wa.Application(config=conf, middlewares=middlewares, lifespan=middleware.lifespan, debug=conf.debug)
    app.add('/host/certificate', endpoint.sign_host, methods=['POST'])
    app.add('/host/ca', endpoint.read_host_signing_keys, methods=['GET'])
    app.add('/user/certificate', endpoint.sign_user, methods=['POST'])
    app.add('/user/ca', endpoint.read_user_signing_keys, methods=['GET'])
    return app
