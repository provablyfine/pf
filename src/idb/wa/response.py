import dataclasses
import json as json_library


@dataclasses.dataclass(frozen=True)
class Response:
    status_code: int
    headers: dict = dataclasses.field(default_factory=dict)
    body: bytes = b''


class JSONResponse(Response):
    def __init__(self, status_code, json, headers=None):
        if headers is None:
            headers = {}
        headers['Content-Type'] = 'application/json'
        body = json_library.dumps(json).encode('utf-8')
        super().__init__(status_code=status_code, headers=headers, body=body)


class ProblemResponse(JSONResponse):
    def __init__(self, status_code, type=None, title=None, detail=None, instance=None):
        if type is None:
            type = 'about:blank'
        problem = {'status': status_code, 'type': type}
        if title is not None:
            problem['title'] = title
        if detail is not None:
            problem['detail'] = detail
        if instance is not None:
            problem['instance'] = instance
        super().__init__(status_code=status_code, json=problem)
