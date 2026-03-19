import collections.abc

import pydantic

from . import middleware, request, response


class Middleware(middleware.Middleware):
    def __call__(self, request: request.Request, iterator: collections.abc.Iterator[middleware.Middleware]) -> response.Response:
        next_middleware = next(iterator)
        try:
            next_response = next_middleware(request, iterator)
        except pydantic.ValidationError as e:
            assert len(e.errors()) > 0
            error = e.errors()[0]
            return response.ProblemResponse(status_code=400, title='Request invalid.', detail=f'{error["msg"]}: {".".join(map(str, error["loc"]))}')
        return next_response
