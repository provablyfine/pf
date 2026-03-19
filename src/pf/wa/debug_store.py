import collections.abc
import random

from .middleware import Middleware
from .request import Request
from .response import JSONResponse, ProblemResponse, Response


class InMemoryDebugStore:
    def __init__(self, prefix=None, max_size=10000):
        if prefix is None:
            prefix = "/debug/"
        self._prefix = prefix
        self._max_size = max_size
        self._store = {}
        self._id_rng = random.Random()

    @property
    def prefix(self):
        return self._prefix

    def add(self, data):
        if len(self._store) > self._max_size:
            first = next(iter(self._store))
            self._store.pop(first)
        id = self._id_rng.randbytes(4).hex()
        self._store[id] = data
        return self._prefix + id

    def get(self, id):
        return self._store.get(id)


class DebugStoreMiddleware(Middleware):
    def __init__(self, store, prefix=None):
        self._store = store

    def __call__(self, request: Request, iterator: collections.abc.Iterator[Middleware]) -> Response:
        if request.url.path.startswith(self._store.prefix):
            remaining = request.url.path[len(self._store.prefix) :]
            slash = remaining.find("/")
            if slash == -1:
                data = self._store.get(remaining)
                if data is None:
                    return ProblemResponse(
                        status_code=404, title="Debug data could not be found", detail=f"Missing {remaining}"
                    )
                return JSONResponse(status_code=200, json=data)

        request.state.debug_store = self._store
        next_middleware = next(iterator)
        response = next_middleware(request, iterator)
        return response
