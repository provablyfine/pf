import collections.abc
import dataclasses
import http.client
import logging
import traceback
import types
import urllib.parse

import webob
import webob.multidict

from . import exceptions, middleware, request, response

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class Match:
    handler: collections.abc.Callable[[request.Request], response.Response]
    params: collections.abc.Mapping


class Route:
    def __init__(self, path, handler, methods):
        self._segments = path.split("/")
        self._handler = handler
        self._methods = methods

    def match(self, method: str, segments: list[str]) -> Match | None:
        if len(segments) != len(self._segments):
            return None
        if method not in self._methods:
            return None
        params = {}
        for expected, got in zip(self._segments, segments):
            if expected != got:
                if not expected.startswith("<"):
                    return None
                if not expected.endswith(">"):
                    return None
                colon = expected.find(":")
                if colon == -1:
                    return None
                type_str = expected[1:colon]
                name_str = expected[colon + 1 : -1]
                match type_str:
                    case "int":
                        try:
                            value = int(got)
                        except ValueError:
                            return None
                    case "str":
                        value = got
                    case _:
                        logger.error(f"Unexpected path parameter type: {type_str}")
                        return None
                params[name_str] = value
        return Match(handler=self._handler, params=params)


class RoutingMiddleware(middleware.Middleware):
    """
    An internal middleware used by the main application to hold
    the endpoint handler that will be processed at the bottom
    of the middleware stack
    """

    def __init__(self):
        self._routes = []

    def add(self, path, handler, methods=None):
        self._routes.append(Route(path=path, handler=handler, methods=methods))

    def _find_route(self, method, path):
        segments = path.split("/")
        for route in self._routes:
            match = route.match(method, segments)
            if match is None:
                continue
            return match
        return None

    def __call__(
        self, req: request.Request, iterator: collections.abc.Iterator[middleware.Middleware]
    ) -> response.Response:
        next_middleware = next(iterator, None)
        if next_middleware is not None:
            return response.ProblemResponse(status_code=500, title="Routing middleware should be last")
        match = self._find_route(req.method, req.url.path)
        if match is None:
            return response.ProblemResponse(status_code=404, title="No handler found for request")
        req.path_params.set(match.params)
        return match.handler(req)


class Application:
    """
    A WSGI application that does simple request routing
    and handles request parsing/response generation
    """

    def __init__(self, config, middlewares=None, lifespan=None, debug=False):
        if middlewares is None:
            middlewares = []
        self._config = config
        self._state = types.SimpleNamespace()
        self._middlewares = middlewares
        self._debug = debug
        self._router = RoutingMiddleware()
        if lifespan is None:
            self._lifespan = None
        else:
            self._lifespan = lifespan(self._config, self._state).__enter__()

    def __del__(self):
        if self._lifespan is not None:
            self._lifespan.__exit__(None, None, None)

    def add(self, path, handler, methods=None):
        self._router.add(path, handler, methods=methods)

    def __call__(self, environ, start_response):
        webob_request = webob.Request(environ)
        req = request.Request(
            app=request.App(config=self._config, state=self._state),
            method=webob_request.method,
            url=urllib.parse.urlparse(webob_request.url),
            headers=webob.multidict.MultiDict(webob_request.headers.items()),
            query_params=webob_request.GET,
            # XXX: We do not use forms and we are going to migrate away from this code
            form=webob.multidict.MultiDict(),
            state=types.SimpleNamespace(),
            body=webob_request.body,
            cookies=dict(webob_request.cookies),
        )
        iterator = iter([*self._middlewares, self._router])
        first = next(iterator, None)
        assert first is not None, "The list has at least ONE element"

        try:
            resp = first(req, iterator)
            if resp is None:
                resp = response.ProblemResponse(
                    status_code=500,
                    title="InternalServerError",
                    detail=f"Server endpoint did not return a response path: {req.url.path} method: {req.method}",
                )
        except exceptions.HTTPException as e:
            resp = e.response
        except BaseException:
            if self._debug:
                logger.error(traceback.format_exc())
            resp = response.ProblemResponse(
                status_code=500,
                title="Internal Server Error",
                detail="Unexpected error. Setup the backtrace middleware to get more details",
            )
        status_str = http.client.responses[resp.status_code]
        start_response(f"{resp.status_code} {status_str}", list(resp.headers.items()))
        yield resp.body
