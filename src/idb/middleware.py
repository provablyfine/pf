import contextlib
import types
import collections.abc


import sqlalchemy
import cryptography

from . import wa
from . import config
from . import dao_factory
from . import base64url
from . import db
from .context import ctx


@contextlib.contextmanager
def lifespan(config: config.Config, state: types.SimpleNamespace):
    engine = sqlalchemy.create_engine(config.database_url, echo=config.debug_sql)
    with open(config.kek_filename, 'rb') as f:
        kek = base64url.encode(f.read()) + '======'
    state.db_engine = engine
    state.kek = kek
    yield


class ConfigContext:
    def __call__(self,  request: wa.Request, iterator: collections.abc.Iterator[wa.Middleware]) -> wa.Response:
        next_iterator = next(iterator)
        with ctx.set_config(request.app.state.config):
            return next_iterator(request, iterator)


class DbContext:
    def __call__(self, request: wa.Request, iterator: collections.abc.Iterator[wa.Middleware]) -> wa.Response:
        next_iterator = next(iterator)
        with request.app.state.db_engine.begin() as connection:
            dao = dao_factory.create(connection, db.metadata)
            with ctx.set_db(dao), ctx.set_kek(request.app.state.kek):
                return next_iterator(request, iterator)


class KekContext:
    def __call__(self, request: wa.Request, iterator: collections.abc.Iterator[wa.Middleware]) -> wa.Response:
        next_iterator = next(iterator)
        kek = cryptography.fernet.Fernet(request.app.state.kek)
        with ctx.set_kek(kek):
            return next_iterator(request, iterator)
