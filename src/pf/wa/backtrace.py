import collections.abc
import time
import traceback

from . import exceptions, middleware, request, response


class Backtrace:
    def __init__(self, method, path, backtrace):
        self._method = method
        self._path = path
        self._backtrace = backtrace
        self._at = int(time.time())

    def format(self):
        return {"method": self._method, "path": self._path, "at": self._at, "backtrace": self._backtrace}


class BacktraceMiddleware(middleware.Middleware):
    def __call__(
        self, req: request.Request, iterator: collections.abc.Iterator[middleware.Middleware]
    ) -> response.Response:
        next_middleware = next(iterator)
        try:
            resp = next_middleware(req, iterator)
        except exceptions.HTTPException:
            raise
        except BaseException:
            debug_path = req.state.debug_store.add(Backtrace(req.method, req.url.path, traceback.format_exc()).format())
            debug_url = req.app.config.base_url + debug_path
            resp = response.ProblemResponse(status_code=500, title="Internal Server Error", instance=debug_url)
        return resp
