from . import exceptions


def _int_from_bytes_big_endian(data: bytes, *, signed: bool = False) -> int:
    # RFC 4251 mandates network byte order. Python 3.11+ already defaults
    # int.from_bytes to big-endian, so no explicit byteorder kwarg is passed
    # here — the function name documents the convention instead.
    return int.from_bytes(data, signed=signed)


def _int_to_bytes_big_endian(value: int, length: int, *, signed: bool = False) -> bytes:
    return value.to_bytes(length, signed=signed)


class Reader:
    def __init__(self, buffer: bytes):
        self._buffer = buffer
        self._current = 0

    def __len__(self):
        return len(self._buffer)

    @property
    def offset(self) -> int:
        return self._current

    @property
    def has_left(self) -> bool:
        return self._current < len(self._buffer)

    def read_bytes(self, n: int) -> bytes:
        if self._current + n > len(self._buffer):
            raise exceptions.Error("Unable to parse ssh data buffer")
        value = self._buffer[self._current : self._current + n]
        self._current += n
        return value

    def read_uint32(self) -> int:
        buffer = self.read_bytes(4)
        value = _int_from_bytes_big_endian(buffer)
        return value

    def read_uint64(self) -> int:
        buffer = self.read_bytes(8)
        value = _int_from_bytes_big_endian(buffer)
        return value

    def read_string(self) -> bytes:
        length = self.read_uint32()
        return self.read_bytes(length)

    def read_mpint(self) -> int:
        # RFC 4251 Section 5
        buffer = self.read_string()
        if len(buffer) == 0:
            return 0
        return _int_from_bytes_big_endian(buffer, signed=True)


class Writer:
    def __init__(self):
        self._bytes: list[int] = []

    def write_byte(self, b: int):
        self._bytes.extend(b.to_bytes(1))

    def write_uint32(self, value: int):
        self._bytes.extend(_int_to_bytes_big_endian(value, 4))

    def write_uint64(self, value: int):
        self._bytes.extend(_int_to_bytes_big_endian(value, 8))

    def write_bytes(self, buffer: bytes):
        self._bytes.extend(buffer)

    def write_string(self, buffer: bytes):
        self.write_uint32(len(buffer))
        self.write_bytes(buffer)

    def write_nested_string(self, buffer: bytes):
        writer = Writer()
        writer.write_string(buffer)
        self.write_string(writer.to_bytes())

    def write_mpint(self, n: int):
        # RFC 4251 Section 5
        if n < 0:
            nbytes = (n.bit_length() + 7 + 1) // 8
            self.write_string(_int_to_bytes_big_endian(n, nbytes, signed=True))
        elif n > 0:
            nbytes = (n.bit_length() + 7) // 8  # pragma: no mutate
            buffer = _int_to_bytes_big_endian(n, nbytes)
            if buffer[0] & 0x80:
                buffer = b"\x00" + buffer
            self.write_string(buffer)
        else:
            self.write_string(b"")

    def to_bytes(self) -> bytes:
        return bytes(self._bytes)

    def __len__(self):
        return len(self._bytes)
