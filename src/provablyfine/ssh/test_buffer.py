import pytest

from . import buffer, exceptions


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
        (-127, b"\x00\x00\x00\x01\x81"),
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


@pytest.mark.parametrize("value", [0, 1, 2, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF])
def test_uint64(value: int):
    writer = buffer.Writer()
    writer.write_uint64(value)
    reader = buffer.Reader(writer.to_bytes())
    got = reader.read_uint64()
    assert got == value, f"got: {got} expected: {value}"


def test_write_byte():
    writer = buffer.Writer()
    writer.write_byte(0x42)
    assert writer.to_bytes() == b"\x42"


def test_write_nested_string():
    writer = buffer.Writer()
    writer.write_nested_string(b"abc")
    reader = buffer.Reader(writer.to_bytes())
    outer = reader.read_string()
    inner_reader = buffer.Reader(outer)
    assert inner_reader.read_string() == b"abc"


def test_read_bytes_past_end_raises():
    reader = buffer.Reader(b"\x01\x02")
    with pytest.raises(exceptions.Error):
        reader.read_bytes(3)


def test_reader_offset_and_has_left():
    reader = buffer.Reader(b"\x01\x02\x03")
    assert reader.offset == 0
    assert reader.has_left
    assert len(reader) == 3
    reader.read_bytes(2)
    assert reader.offset == 2
    assert reader.has_left
    reader.read_bytes(1)
    assert reader.offset == 3
    assert not reader.has_left


def test_writer_len():
    writer = buffer.Writer()
    assert len(writer) == 0
    writer.write_bytes(b"\x01\x02")
    assert len(writer) == 2
