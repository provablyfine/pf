import types
import dataclasses
import urllib.parse

import webob


@dataclasses.dataclass(frozen=True)
class App:
    config: types.SimpleNamespace
    state: types.SimpleNamespace


class PathParams:
    def __init__(self, params):
        self._params = params

    def __getattr__(self, name):
        return self._params[name]


@dataclasses.dataclass(frozen=True)
class Request:
    app: App
    method: str
    url: urllib.parse.ParseResult
    headers: webob.multidict.MultiDict
    query_params: webob.multidict.MultiDict
    path_params: PathParams
    form: webob.multidict.MultiDict
    state: types.SimpleNamespace
    body: bytes
    cookies: dict
