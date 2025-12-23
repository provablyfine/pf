import time
import traceback
import collections.abc

from .request import Request
from .response import Response, ProblemResponse
from .middleware import Middleware


class Backtrace:
    def __init__(self, method, path, backtrace):
        self._method = method
        self._path = path
        self._backtrace = backtrace
        self._at = int(time.time())

    def format(self):
        return {
            'method': self._method,
            'path': self._path,
            'at': self._at,
            'backtrace': self._backtrace
        }


class BacktraceMiddleware(Middleware):
    def __call__(self, request: Request, iterator: collections.abc.Iterator[Middleware]) -> Response:
        next_middleware = next(iterator)
        try:
            response = next_middleware(request, iterator)
        except BaseException as e:
            debug_path = request.state.debug_store.add(Backtrace(request.method, request.url.path, traceback.format_exc()))
            response = ProblemResponse(status_code=500, title='Internal Server Error', instance=debug_path)
        return response
