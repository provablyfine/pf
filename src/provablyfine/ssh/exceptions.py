class Error(Exception):
    pass


class InvalidConfiguration(Error):
    """A hard environment misconfiguration that prevents the oracle from running
    (e.g. a $TMPDIR too long to hold a UNIX socket). Distinct from a plain
    `Error` so callers can distinguish "misconfigured, surface this to the user"
    from "oracle unavailable, degrade gracefully"."""


class InvalidSignature(Exception):
    pass
