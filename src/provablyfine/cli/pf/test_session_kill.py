import asyncio
import pathlib
import sys

import pytest

from . import session_kill


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


@pytest.mark.skipif(sys.platform != "linux", reason="logind sessions exist on Linux only")
@pytest.mark.parametrize("session_id", ["", "1 2", "-h", "../x", "a" * 33])
def test_a_session_id_that_is_not_a_logind_id_never_reaches_loginctl(session_id: str) -> None:
    assert asyncio.run(session_kill.Terminator(None).terminate("host", "c-1", session_id)) == "invalid session id"


@pytest.mark.skipif(sys.platform == "linux", reason="Linux ends the session with loginctl")
def test_a_host_session_is_ended_through_a_request_for_the_reaper(tmp_path: pathlib.Path) -> None:
    connection_id = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
    terminator = session_kill.Terminator(str(tmp_path))

    assert asyncio.run(terminator.terminate("host", connection_id, "1234")) is None
    assert [p.name for p in tmp_path.iterdir()] == [f"kill-{connection_id}"]


@pytest.mark.skipif(sys.platform == "linux", reason="Linux ends the session with loginctl")
def test_a_host_session_cannot_be_ended_without_a_kill_directory() -> None:
    assert asyncio.run(session_kill.Terminator(None).terminate("host", "c-1", "1")) is not None


def test_logind_start_is_converted_to_the_epoch() -> None:
    # Started 100 seconds ago on the monotonic clock.
    assert session_kill.session_started_at(900_000_000, now=5000.0, monotonic_now=1000.0) == 4900.0


def test_a_session_started_after_the_registered_one_is_a_later_session() -> None:
    assert not session_kill.is_a_later_session(1000.0, 1000)
    assert not session_kill.is_a_later_session(1005.0, 1000)
    assert session_kill.is_a_later_session(1011.0, 1000)
    # The session logind holds is older than the registered one.
    assert not session_kill.is_a_later_session(900.0, 1000)


@pytest.mark.skipif(sys.platform != "linux", reason="logind sessions exist on Linux only")
def test_a_host_session_is_not_ended_when_the_command_has_no_start_time() -> None:
    assert asyncio.run(session_kill.Terminator(None).terminate("host", "c-1", "1")) is not None
