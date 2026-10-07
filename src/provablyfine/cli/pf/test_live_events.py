import asyncio
import os
import time

from . import live_events

CID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"
OTHER = "11111111-2222-4333-8444-555555555555"


def _event(kind: live_events.EventKind = "start", cid: str = CID, session_id: str = "7", at: int = 100):
    return live_events.Event(kind=kind, connection_id=cid, session_id=session_id, at=at)


def test_events_are_read_back_oldest_first(tmp_path):
    clock = iter([1.0, 2.0, 3.0])
    events = [_event("start"), _event("end", at=200), _event("start", cid=OTHER)]
    for event in events:
        assert live_events.write_event(str(tmp_path), event, now=lambda: next(clock)) is not None

    assert [e for _, e in live_events.read_events(str(tmp_path))] == events


def test_an_invalid_event_is_not_written(tmp_path):
    assert live_events.write_event(str(tmp_path), _event(cid="not-a-uuid")) is None
    assert live_events.write_event(str(tmp_path), _event(session_id="../x")) is None
    assert os.listdir(tmp_path) == []


def test_files_that_are_not_events_are_ignored(tmp_path):
    (tmp_path / "tmpabc").write_text("{}")
    (tmp_path / "0000000000000001-start-aaaaaaaa.json").write_text("not json")
    (tmp_path / "0000000000000002-start-bbbbbbbb.json").write_text('{"connection_id": "x", "session_id": "", "at": 1}')
    (tmp_path / "0000000000000003-start-cccccccc.json").write_text("x" * (live_events.MAX_EVENT_BYTES + 1))
    (tmp_path / "0000000000000004-start-dddddddd.json").write_text(
        f'{{"connection_id": "{CID}", "session_id": "", "at": true}}'
    )

    assert live_events.read_events(str(tmp_path)) == []


def test_accepted_events_are_removed(tmp_path):
    live_events.write_event(str(tmp_path), _event())
    received: list[live_events.Event] = []

    async def send(event: live_events.Event) -> None:
        received.append(event)

    assert asyncio.run(live_events.forward(str(tmp_path), send)) == 1
    assert received == [_event()]
    assert os.listdir(tmp_path) == []


def test_a_failed_event_is_kept_and_holds_back_its_own_session_only(tmp_path):
    clock = iter([1.0, 2.0, 3.0])
    live_events.write_event(str(tmp_path), _event("start"), now=lambda: next(clock))
    live_events.write_event(str(tmp_path), _event("end"), now=lambda: next(clock))
    live_events.write_event(str(tmp_path), _event("start", cid=OTHER), now=lambda: next(clock))
    received: list[live_events.Event] = []

    async def send(event: live_events.Event) -> None:
        if event.connection_id == CID:
            raise OSError("server down")
        received.append(event)

    assert asyncio.run(live_events.forward(str(tmp_path), send)) == 1
    assert [e.connection_id for e in received] == [OTHER]
    assert [e.kind for _, e in live_events.read_events(str(tmp_path))] == ["start", "end"]


def test_old_files_are_removed(tmp_path):
    path = live_events.write_event(str(tmp_path), _event())
    assert path is not None
    old = time.time() - 1000
    os.utime(path, (old, old))

    async def send(event: live_events.Event) -> None:
        raise OSError("server down")

    asyncio.run(live_events.forward(str(tmp_path), send))

    assert os.listdir(tmp_path) == []


def test_events_written_at_the_same_instant_keep_their_order(tmp_path):
    events = [_event("start"), _event("end", at=200), _event("start", session_id="8")]
    for event in events:
        live_events.write_event(str(tmp_path), event, now=lambda: 5.0)

    assert [e for _, e in live_events.read_events(str(tmp_path))] == events
