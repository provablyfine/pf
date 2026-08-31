import pytest

from . import duration


@pytest.mark.parametrize(
    "text,seconds",
    [
        ("3600", 3600),  # a bare number stays seconds
        ("90s", 90),
        ("90m", 5400),
        ("1h30m", 5400),
        ("24h", 86400),
        ("2d", 172800),
        ("1d12h30m15s", 131415),
        (" 8H ", 28800),  # whitespace and case
    ],
)
def test_parse(text: str, seconds: int):
    assert duration.parse(text) == seconds


@pytest.mark.parametrize(
    "text",
    [
        "",
        "0",
        "0h",  # a grant needs a positive TTL
        "1h30",  # a trailing number without a unit is a typo, not 30 seconds
        "1 h",
        "1h garbage",
        "-5m",
        "abc",
        "1w",
    ],
)
def test_parse_rejects(text: str):
    assert duration.parse(text) is None


@pytest.mark.parametrize(
    "seconds,text",
    [
        (90, "1m30s"),
        (3600, "1h"),
        (5400, "1h30m"),
        (28800, "8h"),
        (86400, "24h"),  # days are read but never written
        (172800, "48h"),
    ],
)
def test_to_text(seconds: int, text: str):
    assert duration.to_text(seconds) == text
    assert duration.parse(text) == seconds
