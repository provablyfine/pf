import pathlib

from . import session_kill

CONNECTION_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
OTHER_CONNECTION_ID = "11111111-2222-3333-4444-555555555555"


def test_every_tunnel_of_the_connection_is_closed_and_the_others_are_not(tmp_path: pathlib.Path) -> None:
    terminator = session_kill.Terminator(str(tmp_path))
    closed: list[str] = []
    terminator.track_tunnel(CONNECTION_ID, "jti-1", lambda: closed.append("jti-1"))
    terminator.track_tunnel(CONNECTION_ID, "jti-2", lambda: closed.append("jti-2"))
    terminator.track_tunnel(OTHER_CONNECTION_ID, "jti-3", lambda: closed.append("jti-3"))

    assert terminator.terminate(CONNECTION_ID) is None
    assert sorted(closed) == ["jti-1", "jti-2"]


def test_a_finished_tunnel_is_no_longer_closed(tmp_path: pathlib.Path) -> None:
    terminator = session_kill.Terminator(str(tmp_path))
    closed: list[str] = []
    terminator.track_tunnel(CONNECTION_ID, "jti-1", lambda: closed.append("jti-1"))
    terminator.track_tunnel(CONNECTION_ID, "jti-2", lambda: closed.append("jti-2"))
    terminator.untrack_tunnel(CONNECTION_ID, "jti-1")

    terminator.terminate(CONNECTION_ID)

    assert closed == ["jti-2"]


def test_the_host_session_is_ended_through_a_request_for_the_reaper(tmp_path: pathlib.Path) -> None:
    terminator = session_kill.Terminator(str(tmp_path))

    assert terminator.terminate(CONNECTION_ID) is None
    assert [p.name for p in tmp_path.iterdir()] == [f"kill-{CONNECTION_ID}"]


def test_a_connection_without_tunnels_cannot_be_ended_without_a_kill_directory() -> None:
    assert session_kill.Terminator(None).terminate(CONNECTION_ID) is not None


def test_a_tunnel_is_enough_when_there_is_no_kill_directory() -> None:
    terminator = session_kill.Terminator(None)
    closed: list[str] = []
    terminator.track_tunnel(CONNECTION_ID, "jti-1", lambda: closed.append("jti-1"))

    assert terminator.terminate(CONNECTION_ID) is None
    assert closed == ["jti-1"]


def test_a_connection_id_with_an_unexpected_shape_writes_no_request(tmp_path: pathlib.Path) -> None:
    assert session_kill.Terminator(str(tmp_path)).terminate("../x") is not None
    assert list(tmp_path.iterdir()) == []
