import logging
import functools


logger = logging.getLogger(__name__)


def transaction(f):
    @functools.wraps(f)
    async def wrapper(request, *args, **kwargs):
        async with request.app.state.database.transaction() as _:
            request.state.dao = request.app.state.dao
            return await f(request, *args, **kwargs)
    return wrapper
