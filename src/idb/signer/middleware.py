import contextlib
import types
import collections

import cryptography.fernet

from .. import base64url
from .. import wa

from . import config
from .context import ctx


@contextlib.contextmanager
def lifespan(config: config.Config, state: types.SimpleNamespace):
    with open(config.kek_filename, 'rb') as f:
        kek = base64url.encode(f.read()) + '======'
    state.config = config
    state.kek = kek
    yield


class ConfigContext:
    def __call__(self,  request: wa.Request, iterator: collections.abc.Iterator[wa.Middleware]) -> wa.Response:
        next_iterator = next(iterator)
        with ctx.set_config(request.app.state.config):
            return next_iterator(request, iterator)


class KekContext:
    def __call__(self, request: wa.Request, iterator: collections.abc.Iterator[wa.Middleware]) -> wa.Response:
        next_iterator = next(iterator)
        kek = cryptography.fernet.Fernet(request.app.state.kek)
        with ctx.set_kek(kek):
            return next_iterator(request, iterator)
