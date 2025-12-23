from __future__ import annotations
import collections.abc

from .request import Request
from .response import Response, ProblemResponse


class Middleware:
    "The ABC for all middlewares"

    def __call__(self, request: Request, iterator: collections.abc.Iterator[Middleware]) -> Response:
        raise NotImplementedError


class LastMiddleware:
    """
    An internal middleware used by the main application to hold
    the endpoint handler that will be processed at the bottom
    of the middleware stack
    """

    def __init__(self, handler):
        self._handler = handler

    def __call__(self, request: Request, iterator: collections.abc.Iterator[Middleware]) -> Response:
        next_middleware = next(iterator, None)
        if next_middleware is not None:
            return ProblemResponse(status_code=500, title='Last middleware should be last')
        return self._handler(request)
