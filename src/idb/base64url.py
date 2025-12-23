import base64


def decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=======")


def encode(s: bytes) -> str:
    return base64.urlsafe_b64encode(s).decode().rstrip('=')
