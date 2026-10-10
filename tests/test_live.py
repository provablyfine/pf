"""Integration tests for the live session registry."""

import asyncio
import time
import typing

import provablyfine_client as pfc
import pytest

import provablyfine.cli.pf.live_events

from . import test_identity_self_token as base


def _report(
    connection_id: str, *, kind: typing.Literal["relay", "host"] = "host", session_id: str = "", at: int | None = None
):
    return pfc.schemas.LiveReportRequest(
        connection_id=connection_id,
        kind=kind,
        session_id=session_id,
        at=int(time.time()) if at is None else at,
    )


def _signed_in(api, tmp_path):
    factory, identity_name, role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    base._grant_shell(sc, role_id, identity_name, max_session_ttl_s=3600)
    return factory, sc, identity_name


def test_a_started_session_is_listed_until_it_ends(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    connection_id = base._sign_cert(sc, host)

    sc.report_live("start", _report(connection_id, session_id="42"))
    [session] = sc.list_live(active=True).sessions
    assert session.connection_id == connection_id
    assert session.hostname == host
    assert session.session_id == "42"
    assert session.ended_at is None
    assert session.deadline is not None

    sc.report_live("end", _report(connection_id, session_id="42"))
    assert sc.list_live(active=True).sessions == []
    [ended] = sc.list_live(active=False).sessions
    assert ended.ended_at is not None


def test_reporting_twice_changes_nothing(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    connection_id = base._sign_cert(sc, host)

    sc.report_live("start", _report(connection_id, session_id="1", at=int(time.time()) - 5))
    sc.report_live("start", _report(connection_id, session_id="1"))
    sc.report_live("end", _report(connection_id, session_id="1", at=int(time.time()) - 2))
    first_end = sc.list_live().sessions[0].ended_at
    sc.report_live("end", _report(connection_id, session_id="1"))

    [session] = sc.list_live().sessions
    assert session.ended_at == first_end


def test_a_certificate_used_twice_gives_two_sessions(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    connection_id = base._sign_cert(sc, host)

    sc.report_live("start", _report(connection_id, session_id="1"))
    sc.report_live("start", _report(connection_id, session_id="2"))
    sc.report_live("end", _report(connection_id, session_id="1"))

    sessions = {s.session_id: s for s in sc.list_live().sessions}
    assert sessions["1"].ended_at is not None
    assert sessions["2"].ended_at is None


def test_an_end_without_a_session_id_ends_every_open_session_of_the_connection(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    connection_id = base._sign_cert(sc, host)
    sc.report_live("start", _report(connection_id, session_id="1"))
    sc.report_live("start", _report(connection_id, session_id="2"))

    sc.report_live("end", _report(connection_id, session_id=""))

    assert sc.list_live(active=True).sessions == []


def test_relay_and_host_sessions_are_kept_apart(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    connection_id = base._sign_cert(sc, host)
    sc.report_live("start", _report(connection_id, kind="relay"))
    sc.report_live("start", _report(connection_id, kind="host", session_id="7"))
    sc.report_live("end", _report(connection_id, kind="relay"))

    kinds = {s.kind: s.ended_at is None for s in sc.list_live().sessions}
    assert kinds == {"relay": False, "host": True}


def test_an_unknown_connection_is_rejected(api, tmp_path):
    _, sc, _ = _signed_in(api, tmp_path)

    with pytest.raises(pfc.exceptions.UI):
        sc.report_live("start", _report("11111111-2222-3333-4444-555555555555"))


def test_a_host_cannot_report_a_connection_issued_for_another_host(api, tmp_path):
    factory, _host, role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    sc.create_identity(
        name="other-host", boundary_id_list=[], boundary_name_list=[], tag_id_list=[], tag_name_value_list=[]
    )
    base._grant_shell(sc, role_id, "other-host", max_session_ttl_s=3600)
    connection_id = base._sign_cert(sc, "other-host")

    with pytest.raises(pfc.exceptions.UI):
        sc.report_live("start", _report(connection_id))


def test_listing_needs_the_live_grant(api, tmp_path):
    factory, sc, _host = _signed_in(api, tmp_path)
    other = base._invite_second_identity(factory, sc, api.port, tmp_path)

    with pytest.raises(pfc.exceptions.UI):
        other.list_live()


def test_events_in_the_spool_reach_the_registry(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    connection_id = base._sign_cert(sc, host)
    spool = tmp_path / "spool"
    spool.mkdir()
    now = int(time.time())
    for kind in ("start", "end"):
        event = provablyfine.cli.pf.live_events.Event(kind=kind, connection_id=connection_id, session_id="9", at=now)
        assert provablyfine.cli.pf.live_events.write_event(str(spool), event) is not None

    async def send(event: provablyfine.cli.pf.live_events.Event) -> None:
        sc.report_live(event.kind, _report(event.connection_id, session_id=event.session_id, at=event.at))

    assert asyncio.run(provablyfine.cli.pf.live_events.forward(str(spool), send)) == 2

    [session] = sc.list_live(active=False).sessions
    assert (session.connection_id, session.kind, session.session_id) == (connection_id, "host", "9")
    assert list(spool.iterdir()) == []


def _start_session(sc, host):
    connection_id = base._sign_cert(sc, host)
    sc.report_live("start", _report(connection_id, session_id="42"))
    [session] = sc.list_live(active=True).sessions
    return session


def test_ending_an_unknown_session_is_refused(api, tmp_path):
    _, sc, _host = _signed_in(api, tmp_path)

    with pytest.raises(pfc.exceptions.UI):
        sc.terminate_live("00000000-0000-0000-0000-000000000000")


def test_ending_a_session_that_already_ended_is_refused(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    session = _start_session(sc, host)
    sc.report_live("end", _report(session.connection_id, session_id="42"))

    with pytest.raises(pfc.exceptions.UI):
        sc.terminate_live(session.id)


def test_ending_a_session_needs_the_terminate_grant(api, tmp_path):
    factory, sc, host = _signed_in(api, tmp_path)
    session = _start_session(sc, host)
    other = base._invite_second_identity(factory, sc, api.port, tmp_path)

    with pytest.raises(pfc.exceptions.UI):
        other.terminate_live(session.id)


def test_ending_a_session_fails_when_no_bastion_can_reach_the_host(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)
    session = _start_session(sc, host)

    with pytest.raises(pfc.exceptions.UI, match="Unable to end the session"):
        sc.terminate_live(session.id)

    # The request is recorded even though the host could not be reached.
    assert any(e.type == "live-session-terminate" for e in sc.list_audit_log().entries)
    # The registry is not touched: the host reports the end of the session itself.
    assert [s.id for s in sc.list_live(active=True).sessions] == [session.id]


def test_a_terminate_token_cannot_be_requested_from_the_self_token_endpoint(api, tmp_path):
    _, sc, host = _signed_in(api, tmp_path)

    with pytest.raises(pfc.exceptions.UI):
        sc.get_self_token("bastion", hostname=host, purpose=typing.cast(typing.Literal["register"], "terminate"))


def _viewer(factory, sc, api, tmp_path, tag_list):
    """A second identity whose only role has a live grant limited to hosts with these tags."""
    other = base._invite_second_identity(factory, sc, api.port, tmp_path)
    role = sc.create_role("viewer", "")
    live = pfc.schemas.validate_grant(
        {"type": "live", "filter": {"tag_list": tag_list}, "permission": {"read": True, "terminate": True}}
    )
    sc.update_role(role.id, grant_list=[live], member_list=[pfc.schemas.RoleMemberUpdateRequest(name="second")])
    other.update_session(role.id)
    return other, role.id


def test_a_tag_filter_limits_the_sessions_a_grant_covers(api, tmp_path):
    factory, sc, host = _signed_in(api, tmp_path)
    prod = sc.create_tag("env", "prod")
    session = _start_session(sc, host)
    other, _ = _viewer(factory, sc, api, tmp_path, [{"name": "env", "value": "prod"}])

    # The host does not hold the tag yet.
    assert other.list_live().sessions == []
    with pytest.raises(pfc.exceptions.UI, match="does not exist"):
        other.terminate_live(session.id)

    sc.update_identity(sc.get_self().id, tags=[pfc.schemas.IdentityTagOp(type="add", tag_id_list=[prod.id])])
    assert [s.id for s in other.list_live().sessions] == [session.id]
    # The session is visible now, so the request gets as far as the bastions.
    with pytest.raises(pfc.exceptions.UI, match="Unable to end the session"):
        other.terminate_live(session.id)


def test_deleting_a_tag_drops_the_live_grants_that_name_it(api, tmp_path):
    factory, sc, _host = _signed_in(api, tmp_path)
    prod = sc.create_tag("env", "prod")
    _, role_id = _viewer(factory, sc, api, tmp_path, [{"name": "env", "value": "prod"}])
    assert [g.type for g in sc.get_role(role_id).grant_list] == ["live"]

    sc.delete_tag(prod.id)

    assert sc.get_role(role_id).grant_list == []
