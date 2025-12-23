import typing
import collections.abc
import time

import openapi_core.datatypes

from . import middleware
from . import request
from . import response

class OpenAPIRequest:
    def __init__(self, request: request.Request):
        self.parameters = openapi_core.datatypes.RequestParameters(
            query=request.query_params,
            header=request.headers,
            cookie=request.cookies,
        )
        self._request = request

    @property
    def host_url(self) -> str:
        host_url = f'{self._request.url.scheme}://{self._request.url.netloc}'
        return host_url

    @property
    def path(self) -> str:
        return self._request.url.path

    @property
    def method(self) -> str:
        return self._request.method.lower()

    @property
    def body(self) -> typing.Optional[bytes]:
        return self._request.body

    @property
    def content_type(self) -> str:
        return self._request.headers.get("Content-Type", "application/octet-stream")


class OpenAPIResponse:
    def __init__(self, response: response.Response):
        self._response = response

    @property
    def data(self) -> bytes:
        return self._response.body

    @property
    def status_code(self) -> int:
        return self._response.status_code

    @property
    def content_type(self) -> str:
        return self._response.headers.get('Content-Type', 'application/octet-stream')

    @property
    def headers(self):
        return self._response.headers


class Middleware(middleware.Middleware):
    def __init__(self, openapi):
        self._openapi = openapi

    def __call__(self, request: request.Request, iterator: collections.abc.Iterator[middleware.Middleware]) -> response.Response:
        next_middleware = next(iterator)
        oapi_request = OpenAPIRequest(request)
        try:
            self._openapi.validate_request(oapi_request)
        except openapi_core.validation.request.exceptions.InvalidRequestBody as e:
            return response.ProblemResponse(status_code=400, title='Request validation error', detail=str(e.__cause__))
        next_response = next_middleware(request, iterator)
        if next_response is None:
            return response.ProblemResponse(status_code=500, title='Internal Server Error', detail='Unexpected error. Setup the backtrace middleware to get more details')
        oapi_response = OpenAPIResponse(next_response)
        try:
            self._openapi.validate_response(oapi_request, oapi_response)
        except openapi_core.validation.response.exceptions.ResponseValidationError as e:
            error_path = request.state.debug_store.add({'method': request.method, 'path': request.url.path, 'validation_error': str(e), 'at': int(time.time())})
            error_url = request.app.config.base_url + error_path
            return response.ProblemResponse(status_code=500, title='Response validation error', instance=error_url)
        return next_response
