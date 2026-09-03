import re

import textual.suggester

_UNIT_S = {"d": 86400, "h": 3600, "m": 60, "s": 1}
_DURATION = re.compile(r"(?:\d+[dhms])+")
_TOKEN = re.compile(r"(\d+)([dhms])")


def parse(text: str) -> int | None:
    """Seconds from '3600', '8h' or '1h30m'. None when the text is not a duration.

    A bare number is seconds, which is what the field held before it learned
    units and what `pfa grant ssh --max-session-ttl` still takes.
    """
    value = text.strip().lower()
    if value.isdigit():
        return int(value) or None
    # fullmatch, not findall: '1h30' and '1h garbage' both contain a token.
    if not _DURATION.fullmatch(value):
        return None
    return sum(int(n) * _UNIT_S[unit] for n, unit in _TOKEN.findall(value)) or None


def to_text(seconds: int) -> str:
    """The inverse, for a stored grant: 5400 -> '1h30m', 86400 -> '24h'.

    No day unit on output. `d` is accepted on input, but a session bound spelled
    '48h' stays comparable to the '8h' next to it, where '2d' would not.
    """
    hours, rest = divmod(seconds, 3600)
    minutes, rest = divmod(rest, 60)
    parts = [f"{n}{unit}" for n, unit in ((hours, "h"), (minutes, "m"), (rest, "s")) if n]
    return "".join(parts) or "0s"


class Suggester(textual.suggester.Suggester):
    """Renders the value the field is about to store as dim text after it.

    The grant holds seconds, so a duration is always a conversion the user has
    to trust. This shows the result of it while they type, and answers the one
    genuinely ambiguous entry, a bare number.
    """

    def __init__(self) -> None:
        super().__init__(case_sensitive=True)

    async def get_suggestion(self, value: str) -> str | None:
        seconds = parse(value)
        if seconds is None:
            return None
        return f"{value}  = {seconds} second" + ("" if seconds == 1 else "s")
