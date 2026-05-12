import functools
import typing

from .. import jwk, ssh
from . import exceptions

P = typing.ParamSpec("P")
R = typing.TypeVar("R")


def exception(f: typing.Callable[P, R]) -> typing.Callable[P, R]:  # noqa: UP047
    @functools.wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return f(*args, **kwargs)
        except ssh.exceptions.Error as e:
            raise exceptions.UI(str(e))

    return wrapper


def load_private_key(data: bytes, password: bytes | None = None) -> jwk.Private:
    try:
        return jwk.Private.from_pem(data, password)
    except Exception:
        pass
    try:
        return jwk.Private.from_openssh(data)
    except Exception:
        raise exceptions.UI("Unable to load key as either a PEM or an OpenSSH-formatted public key")
