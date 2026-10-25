import provablyfine_client as pfc

from . import test_identity_self_token as base


def _request_shell_ticket(sc: pfc.SessionClient, hostname: str, username: str):
    return sc._session.post(
        f"{sc._directory.ssh}/user/shell-ticket",
        auth=sc._auth(),
        json={"hostname": hostname, "username": username},
    )


def test_a_shell_ticket_is_issued_when_granted(api, tmp_path):
    factory, host, role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()
    base._grant_shell(sc, role_id, host, max_session_ttl_s=3600)

    response = _request_shell_ticket(sc, host, "root")

    assert response.status_code == 200
    assert response.json()["ticket"]


def test_a_shell_ticket_is_refused_without_the_grant(api, tmp_path):
    factory, host, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()

    response = _request_shell_ticket(sc, host, "root")

    assert response.status_code == 403


def test_a_shell_ticket_is_refused_for_an_unknown_host(api, tmp_path):
    factory, _host, _role_id = base._setup_session(api.port, tmp_path)
    sc = factory.session()

    response = _request_shell_ticket(sc, "no-such-host", "root")

    assert response.status_code == 404
