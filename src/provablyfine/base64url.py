import base64


def decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=======")


def encode(s: bytes) -> str:
    return base64.urlsafe_b64encode(s).decode().rstrip("=")


def decode_uint(s: str) -> int:
    decoded = decode(s)
    return int.from_bytes(decoded, byteorder="big")


def encode_uint(i: int) -> str:
    byte_length = (i.bit_length() + 7) // 8 or 1
    der_bytes = i.to_bytes(byte_length, byteorder="big")
    return encode(der_bytes)
