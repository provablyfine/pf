from .. import ssh
from . import exceptions


def exception(f):
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ssh.exceptions.Error as e:
            raise exceptions.UI(str(e))
    return wrapper
