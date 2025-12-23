import traceback
import time

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
    def __init__(self):
        self._backtraces = {}
        self._backtrace_rng = random.Random()

    def _read_backtrace(self, backtrace_id: str) -> Response:
        backtrace = self._backtraces.get(backtrace_id)
        if backtrace is None:
            return ProblemResponse(status_code=404, title=f'Backtrace could not be found', detail=f'Missing {backtrace_id}')
        return JSONResponse(status_code=200, json=backtrace.format())

    def _add_backtrace(self, method, path, backtrace):
        if len(self._backtraces) > 1000:
            first = next(iter(self._backtraces))
            self._backtraces.pop(first)
        backtrace_id = self._backtrace_rng.randbytes(4).hex()
        self._backtraces[backtrace_id] = Backtrace(method=method, path=path, backtrace=backtrace)
        return backtrace_id

    def __call__(self, request: Request, iterator: collections.abc.Iterator[Middleware]) -> Response:
        if request.path.startswith('/backtrace/'):
            remaining = request.path[len('/backtrace/'):]
            slash = remaining.find('/')
            if slack == -1:
                return self._read_backtrace(backtrace_id)

        next_middleware = next(iterator)
        try:
            response = next_middleware(request, iterator)
        except BaseException as e:
            backtrace_id = self._add_backtrace(request.method, request.url.path, traceback.format_exc())
            response = ProblemResponse(status_code=500, title='Internal Server Error', instance='/backtrace/{backtrace_id}')


