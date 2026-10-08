import asyncio
import pathlib

from . import session_kill

CONNECTION_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


def test_a_tracked_tunnel_is_closed() -> None:
    terminator = session_kill.Terminator(None)
    closed: list[str] = []
    terminator.track_tunnel("jti-1", lambda: closed.append("jti-1"))

    assert asyncio.run(terminator.terminate("relay", "c-1", "jti-1")) is None
    assert closed == ["jti-1"]


def test_an_unknown_or_finished_tunnel_is_refused() -> None:
    terminator = session_kill.Terminator(None)
    terminator.track_tunnel("jti-1", lambda: None)
    terminator.untrack_tunnel("jti-1")

    assert asyncio.run(terminator.terminate("relay", "c-1", "jti-1")) == "no such tunnel"
    assert asyncio.run(terminator.terminate("relay", "c-1", "jti-2")) == "no such tunnel"


def test_an_unknown_kind_is_refused() -> None:
    assert asyncio.run(session_kill.Terminator(None).terminate("other", "c-1", "1")) == "unknown kind"


def test_a_host_session_is_ended_through_a_request_for_the_reaper(tmp_path: pathlib.Path) -> None:
    terminator = session_kill.Terminator(str(tmp_path))

    assert asyncio.run(terminator.terminate("host", CONNECTION_ID, "1234")) is None
    assert [p.name for p in tmp_path.iterdir()] == [f"kill-{CONNECTION_ID}"]


def test_a_host_session_cannot_be_ended_without_a_kill_directory() -> None:
    assert asyncio.run(session_kill.Terminator(None).terminate("host", CONNECTION_ID, "1")) is not None


def test_a_connection_id_with_an_unexpected_shape_writes_no_request(tmp_path: pathlib.Path) -> None:
    assert asyncio.run(session_kill.Terminator(str(tmp_path)).terminate("host", "../x", "1")) is not None
    assert list(tmp_path.iterdir()) == []
