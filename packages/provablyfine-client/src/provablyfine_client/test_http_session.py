"""HttpSession retries a busy server transparently, honoring the real Retry-After it was sent."""

import requests

from . import exceptions, http_session, http_signatures, signer


class _FakeSession(requests.Session):
    """A requests.Session that returns a scripted sequence of responses instead of connecting."""

    def __init__(self, responses: list[requests.Response]) -> None:
        super().__init__()
        self._responses = list(responses)
        self.sent: list[requests.PreparedRequest] = []

    def send(self, request: requests.PreparedRequest, **kwargs: object) -> requests.Response:
        self.sent.append(request)
        return self._responses.pop(0)


def _response(status_code: int, headers: dict[str, str] | None = None, body: bytes = b"") -> requests.Response:
    r = requests.Response()
    r.status_code = status_code
    r.headers.update(headers or {})
    r._content = body
    return r


def _auth() -> http_signatures.Auth:
    return http_signatures.Auth([signer.HmacSigner("test", b"a-fake-key-for-tests")])


def test_retries_a_busy_response_and_returns_the_eventual_success() -> None:
    fake = _FakeSession([_response(503, {"Retry-After": "0.01"}), _response(200)])
    session = http_session.HttpSession(fake)

    response = session.request("GET", "http://example.com/x")

    assert response.status_code == 200
    assert len(fake.sent) == 2


def test_gives_up_once_the_budget_is_exhausted() -> None:
    # Retry-After (10s) leaves no room within a 0.05s budget: must not retry at all.
    fake = _FakeSession([_response(503, {"Retry-After": "10"})])
    session = http_session.HttpSession(fake)

    response = session.request("GET", "http://example.com/x", timeout=0.05)

    assert response.status_code == 503
    assert len(fake.sent) == 1


def test_does_not_retry_a_busy_response_with_no_retry_after() -> None:
    fake = _FakeSession([_response(503)])
    session = http_session.HttpSession(fake)

    response = session.request("GET", "http://example.com/x")

    assert response.status_code == 503
    assert len(fake.sent) == 1


def test_does_not_retry_an_unparseable_retry_after() -> None:
    fake = _FakeSession([_response(503, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})])
    session = http_session.HttpSession(fake)

    response = session.request("GET", "http://example.com/x")

    assert response.status_code == 503
    assert len(fake.sent) == 1


def test_each_retry_is_signed_fresh() -> None:
    """A retried attempt must not resend the same nonce: the server rejects a reused one."""
    fake = _FakeSession(
        [
            _response(503, {"Retry-After": "0.01"}),
            _response(503, {"Retry-After": "0.01"}),
            _response(200),
        ]
    )
    session = http_session.HttpSession(fake)

    response = session.request("GET", "http://example.com/x", auth=_auth())

    assert response.status_code == 200
    assert len(fake.sent) == 3
    signature_inputs = [p.headers["Signature-Input"] for p in fake.sent]
    assert len(set(signature_inputs)) == 3, "every attempt must carry its own nonce"


def test_non_503_responses_are_returned_on_the_first_attempt() -> None:
    fake = _FakeSession([_response(200)])
    session = http_session.HttpSession(fake)

    response = session.request("GET", "http://example.com/x")

    assert response.status_code == 200
    assert len(fake.sent) == 1


def test_400_is_still_raised_as_ui_unaffected_by_retry_logic() -> None:
    fake = _FakeSession([_response(400, body=b'{"title": "Bad request"}')])
    session = http_session.HttpSession(fake)

    try:
        session.request("GET", "http://example.com/x")
        raise AssertionError("expected exceptions.UI")
    except exceptions.UI as e:
        assert str(e) == "Bad request"
    assert len(fake.sent) == 1
