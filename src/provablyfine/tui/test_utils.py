import pytest

from . import _utils


@pytest.mark.parametrize(
    "s, max_len, expected",
    [
        ("hello", 10, "hello"),
        ("hello", 5, "hello"),
        ("hello world", 5, "hello…"),
        ("", 5, ""),
        ("ab", 1, "a…"),
    ],
)
def test_ellipsize(s: str, max_len: int, expected: str) -> None:
    assert _utils.ellipsize(s, max_len) == expected
