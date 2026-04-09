import pytest

from . import buffer


@pytest.mark.parametrize("value", [0, 1, 2, 127, 128, 129, 255, 256, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF])
def test_uint32(value: int):
    writer = buffer.Writer()
    writer.write_uint32(value)
    reader = buffer.Reader(writer.to_bytes())
    got = reader.read_uint32()
    assert got == value, f"got: {got} expected: {value}"


@pytest.mark.parametrize("value", [b"", b"\x00", b"\xde\xad\xbe\xaf"])
def test_string(value: bytes):
    writer = buffer.Writer()
    writer.write_string(value)
    reader = buffer.Reader(writer.to_bytes())
    got = reader.read_string()
    assert got == value, f"got: {got} expected: {value}"


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, b"\x00\x00\x00\x00"),
        (1, b"\x00\x00\x00\x01\x01"),
        (255, b"\x00\x00\x00\x02\x00\xff"),
        (-1, b"\x00\x00\x00\x01\xff"),
        (-128, b"\x00\x00\x00\x02\xff\x80"),
    ],
)
def test_mpint_writer(value: int, expected: bytes):
    writer = buffer.Writer()
    writer.write_mpint(value)
    got = writer.to_bytes()
    assert got == expected, f"got: {got} expected: {value}"


@pytest.mark.parametrize("value", [0, 1, 2, 127, 128, 129, 255, 256, -1, -127, -128, -129, -255, -((1 << 16) + 1)])
def test_mpint(value: int):
    writer = buffer.Writer()
    writer.write_mpint(value)
    reader = buffer.Reader(writer.to_bytes())
    got = reader.read_mpint()
    assert got == value, f"got: {got} expected: {value}"
