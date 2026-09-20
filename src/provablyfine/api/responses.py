import collections.abc

import fastapi.responses

from . import schemas

# Reusable OpenAPI response entry for RFC 7807 problem responses.
PROBLEM: dict[str, object] = {"model": schemas.problem.ProblemDocument}


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


def not_found(title: str) -> ProblemHTTPException:
    """The response for a missing object.

    Use it for every "does not exist" answer about one kind of object, and for
    objects the caller may not know about, so that the answers cannot be told apart.
    """
    return ProblemHTTPException(problem_response(status_code=404, title=title))


def forbidden_or_not_found(
    can_read: collections.abc.Callable[[], bool],
    title: str,
    not_found_title: str,
    detail: str | None = None,
) -> ProblemHTTPException:
    """The response for an action the caller is not allowed to do on an existing object.

    A caller who cannot read the object gets the same answer as for a missing object.
    Otherwise the status code would tell them that the object exists.
    """
    if not can_read():
        return not_found(not_found_title)
    return ProblemHTTPException(problem_response(status_code=403, title=title, detail=detail))
