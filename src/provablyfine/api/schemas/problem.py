from __future__ import annotations

from . import base


class ProblemDocument(base.APIBase):
    type: str = "about:blank"
    detail: str | None = None
    title: str | None = None
    status: int | None = None
