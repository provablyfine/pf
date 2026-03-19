from . import exceptions


class Reader:
    def __init__(self, buffer):
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
        value = int.from_bytes(buffer, byteorder="big")
        return value

    def read_uint64(self) -> int:
        buffer = self.read_bytes(8)
        value = int.from_bytes(buffer, byteorder="big")
        return value

    def read_string(self) -> bytes:
        length = self.read_uint32()
        return self.read_bytes(length)

    def read_mpint(self) -> int:
        # RFC 4251 Section 5
        buffer = self.read_string()
        if len(buffer) == 0:
            return 0
        return int.from_bytes(buffer, byteorder="big", signed=True)


class Writer:
    def __init__(self):
        self._bytes = []

    def write_byte(self, b: int):
        self._bytes.extend(b.to_bytes(1))

    def write_uint32(self, value: int):
        self._bytes.extend(value.to_bytes(4, byteorder="big"))

    def write_uint64(self, value: int):
        self._bytes.extend(value.to_bytes(8, byteorder="big"))

    def write_bytes(self, buffer):
        if isinstance(buffer, Writer):
            self._bytes.extend(buffer._bytes)
        else:
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
        if n == 0:
            self.write_string(b"")
        elif n > 0:
            nbytes = (n.bit_length() + 7) // 8
            buffer = n.to_bytes(nbytes, byteorder="big")
            if buffer[0] & 0x80:
                buffer = b"\x00" + buffer
            self.write_string(buffer)
        elif n < 0:
            nbytes = (n.bit_length() + 7 + 1) // 8
            self.write_string(n.to_bytes(nbytes, byteorder="big", signed=True))
        else:
            assert False

    def to_bytes(self) -> bytes:
        return bytes(self._bytes)

    def __len__(self):
        return len(self._bytes)
