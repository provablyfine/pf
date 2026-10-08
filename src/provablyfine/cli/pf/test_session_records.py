import pathlib

from . import session_records

CONNECTION_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
OTHER_CONNECTION_ID = "11111111-2222-3333-4444-555555555555"


def test_a_written_session_is_found_by_its_connection_id(tmp_path: pathlib.Path) -> None:
    directory = str(tmp_path / "sessions")
    assert session_records.write(directory, CONNECTION_ID, "42")
    assert session_records.write(directory, CONNECTION_ID, "c3")
    assert session_records.write(directory, OTHER_CONNECTION_ID, "7")

    assert session_records.session_ids(directory, CONNECTION_ID) == ["42", "c3"]
    assert session_records.session_ids(directory, OTHER_CONNECTION_ID) == ["7"]


def test_a_removed_session_is_no_longer_found(tmp_path: pathlib.Path) -> None:
    directory = str(tmp_path)
    session_records.write(directory, CONNECTION_ID, "42")
    session_records.remove(directory, CONNECTION_ID, "42")
    session_records.remove(directory, CONNECTION_ID, "42")

    assert session_records.session_ids(directory, CONNECTION_ID) == []


def test_ids_with_an_unexpected_shape_write_nothing(tmp_path: pathlib.Path) -> None:
    directory = str(tmp_path)
    assert not session_records.write(directory, "../x", "42")
    assert not session_records.write(directory, CONNECTION_ID, "../x")
    assert not session_records.write(directory, CONNECTION_ID, "")
    assert not session_records.write(directory, CONNECTION_ID, "a" * 33)

    assert list(tmp_path.iterdir()) == []


def test_names_that_are_not_records_are_ignored(tmp_path: pathlib.Path) -> None:
    (tmp_path / f"{CONNECTION_ID}-4 2").write_text("")
    (tmp_path / f"{CONNECTION_ID}-42.json").write_text("")
    (tmp_path / f"x{CONNECTION_ID}-42").write_text("")

    assert session_records.session_ids(str(tmp_path), CONNECTION_ID) == []


def test_a_missing_directory_has_no_sessions(tmp_path: pathlib.Path) -> None:
    assert session_records.session_ids(str(tmp_path / "missing"), CONNECTION_ID) == []
