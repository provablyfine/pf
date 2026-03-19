from __future__ import annotations

import collections.abc

from .request import Request
from .response import Response


class Middleware:
    "The ABC for all middlewares"

    def __call__(self, request: Request, iterator: collections.abc.Iterator[Middleware]) -> Response:
        raise NotImplementedError
