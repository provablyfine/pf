class Error(Exception):
    pass


class InvalidConfiguration(Error):
    """A hard environment misconfiguration that prevents the oracle from running
    (e.g. a $TMPDIR too long to hold a UNIX socket). Distinct from a plain
    `Error` so callers can distinguish "misconfigured, surface this to the user"
    from "oracle unavailable, degrade gracefully"."""


class OraclePeerCheckFailed(Error):
    """The endpoint we connected to is not served by a process running as us,
    or its owner could not be read.

    Deliberately not an `OSError`: the client's signers map `OSError` to
    "session expired, log in again", which is exactly the misdiagnosis this
    check exists to prevent.
    """


class InvalidSignature(Exception):
    pass
