import types
import collections.abc
import dataclasses
import traceback
import http.client
import urllib.parse

import webob

from .request import Request, App
from .response import Response, ProblemResponse
from .exceptions import HTTPException
from .middleware import Middleware


@dataclasses.dataclass(frozen=True)
class Match:
    handler: collections.abc.Callable[[Request], Response]
    params: collections.abc.Mapping


class Route:
    def __init__(self, path, handler, methods):
        self._segments = path.split('/')
        self._handler = handler
        self._methods = methods

    def match(self, method: str, segments: list[str]) -> Match:
        if len(segments) != len(self._segments):
            return None
        params = {}
        for expected, got in zip(self._segments, segments):
            if expected != got:
                if not expected.startswith('<'):
                    return None
                if not expected.endswith('>'):
                    return None
                colon = expected.find(':')
                if colon == -1:
                    return None
                type_str = expected[1:colon]
                name_str = expected[colon+1:]
                match type_str:
                    case 'int':
                        try:
                            value = int(got)
                        except ValueError:
                            return None
                    case 'str':
                        value = got
                params[name_str] = value
        return Match(handler=self._handler, params=params)


class RoutingMiddleware(Middleware):
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
        segments = path.split('/')
        for route in self._routes:
            match = route.match(method, segments)
            if match is None:
                continue
            return match
        return None

    def __call__(self, request: Request, iterator: collections.abc.Iterator[Middleware]) -> Response:
        next_middleware = next(iterator, None)
        if next_middleware is not None:
            return ProblemResponse(status_code=500, title='Routing middleware should be last')
        match = self._find_route(request.method, request.url.path)
        if match is None:
            return ProblemResponse(status_code=404, title='No handler found for request')
        request.path_params.set(match.params)
        response = match.handler(request)
        return response


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
        request = Request(
            app=App(config=self._config, state=self._state),
            method=webob_request.method,
            url=urllib.parse.urlparse(webob_request.url),
            headers=webob_request.headers,
            query_params=webob_request.GET,
            form=webob_request.POST,
            state=types.SimpleNamespace(),
            body=webob_request.body,
            cookies=webob.cookies
        )
        iterator = iter(self._middlewares + [self._router])
        first = next(iterator, None)
        assert first is not None, 'The list has at least ONE element'

        try:
            response = first(request, iterator)
            if response is None:
                response = ProblemResponse(status_code=500, title='InternalServerError', detail=f'Server endpoint did not return a response path: {request.url.path} method: {request.method}')
        except HTTPException as e:
            response = e.response
        except BaseException:
            if self._debug:
                print(traceback.format_exc())
            response = ProblemResponse(status_code=500, title='Internal Server Error', detail='Unexpected error. Setup the backtrace middleware to get more details')
        status_str = http.client.responses[response.status_code]
        start_response(f'{response.status_code} {status_str}', list(response.headers.items()))
        yield response.body
