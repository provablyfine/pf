import fastapi.responses


class ProblemHTTPException(Exception):
    """Raised from deep in the call stack to abort a request with an error response."""

    def __init__(self, response: fastapi.responses.Response):
        self.response = response


def problem_response(
    status_code: int,
    type: str = "about:blank",
    title: str | None = None,
    detail: str | None = None,
    instance: str | None = None,
) -> fastapi.responses.JSONResponse:
    content: dict[str, object] = {"status": status_code, "type": type}
    if title is not None:
        content["title"] = str(title)
    if detail is not None:
        content["detail"] = str(detail)
    if instance is not None:
        content["instance"] = instance
    return fastapi.responses.JSONResponse(
        status_code=status_code,
        content=content,
        media_type="application/problem+json",
    )
