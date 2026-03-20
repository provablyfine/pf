from __future__ import annotations

import collections.abc

from . import request, response


class Middleware:
    "The ABC for all middlewares"

    def __call__(self, req: request.Request, iterator: collections.abc.Iterator[Middleware]) -> response.Response:
        raise NotImplementedError
