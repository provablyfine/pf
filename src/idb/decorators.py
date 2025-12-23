import logging
import functools

from . import dao_factory
from . import db


logger = logging.getLogger(__name__)


def transaction(f):
    @functools.wraps(f)
    def wrapper(request, *args, **kwargs):
        with request.app.state.db_engine.begin() as connection:
            request.state.db_connection = connection
            request.state.dao = dao_factory.create(connection, db.metadata)
            return f(request, *args, **kwargs)
    return wrapper
