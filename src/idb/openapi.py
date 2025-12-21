import typing
import logging
import os.path
import urllib

import yaml
import starlette
import openapi_core.contrib.starlette.middlewares
import openapi_core


from . import config


logger = logging.getLogger(__name__)

# We implement our own middleware that is based on the
# openapi_core contrib middleware to control the format
# of error responses

class ErrorsHandler(openapi_core.contrib.starlette.middlewares.StarletteOpenAPIErrorsHandler):
    def __call__(
        self,
        errors: typing.Iterable[Exception],
    ) -> starlette.responses.JSONResponse:
        causes = [error if error.__cause__ is None else error.__cause__ for error in errors]
        status_code = max([self.OPENAPI_ERROR_STATUS.get(error.__class__, 400) for error in causes])
        body = {
            'type': 'about:blank',
            'title': 'Malformed content',
            'detail': ', '.join([str(error) for error in causes]),
            'status': status_code
        }
        return starlette.responses.JSONResponse(body, status_code=status_code)


class Middleware(openapi_core.contrib.starlette.middlewares.StarletteOpenAPIMiddleware):
    errors_handler = ErrorsHandler()


def _load_specification():
    filename = os.path.join(os.path.dirname(__file__), 'openapi.yaml')
    with open(filename) as f:
        specification = yaml.safe_load(f)
    specification['servers'] = [
        {"url": config.BASE_URL, 'description': specification['servers'][0]['description']}
    ]
    return specification


def _validate_uri(value):
    parsed = urllib.parse.urlparse(value)
    return parsed.scheme in ['http', 'https']


def create_middleware():
    openapi_config = openapi_core.Config()
    openapi_config.extra_format_validators = {
        'uri': _validate_uri
    }
    middleware = [
        starlette.middleware.Middleware(
            Middleware,
            openapi=openapi_core.OpenAPI.from_dict(_load_specification(), config=openapi_config)
        ),
    ]
    return middleware
