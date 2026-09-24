"""The invitation email goes out once the invitation is committed, and a failure is reported."""

import os
import pathlib
import sqlite3
import tempfile
import threading
import time

import provablyfine_client as pfc
import pytest

import provablyfine.client
import tests.tui_support

from . import utils

FAKE_SENDMAIL = str(pathlib.Path(__file__).parent / "fake_sendmail.sh")
EMAIL = {"email": {"type": "sendmail", "from_address": "pf@example.com", "sendmail_path": FAKE_SENDMAIL}}


@pytest.fixture
def sent_mail(tmp_path, monkeypatch) -> pathlib.Path:
    """Where the fake sendmail keeps the message. Ask for it before `api`: the server inherits the environment."""
    path = tmp_path / "sent.eml"
    monkeypatch.setenv("FAKE_SENDMAIL_OUT", str(path))
    return path


@pytest.fixture
def failing_mail(monkeypatch) -> None:
    monkeypatch.setenv("FAKE_SENDMAIL_FAIL", "1")


def _session_and_identity(api, tmpdir: str) -> tuple[pfc.SessionClient, int]:
    tests.tui_support._setup(api, tmpdir)
    config = provablyfine.client.Config.load(os.path.join(tmpdir, "config.json"))
    session = provablyfine.client.Factory(config, timeout=30).session()
    identity = session.create_identity("alice@example.com", [], [], [], [])
    return session, identity.id


@pytest.mark.parametrize("api", [EMAIL], indirect=True)
def test_email_waits_for_the_commit(sent_mail, api) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        session, identity_id = _session_and_identity(api, tmpdir)

        # An open read transaction from outside makes the server's COMMIT wait.
        reader = sqlite3.connect(utils.root_tenant_db_path(api), isolation_level=None)
        reader.execute("BEGIN")
        reader.execute("SELECT count(*) FROM tag").fetchall()

        request = threading.Thread(target=lambda: session.invite_identity(identity_id, "email"))
        request.start()
        try:
            time.sleep(1.5)
            assert request.is_alive()
            assert not sent_mail.exists(), "the email was sent before the invitation was committed"
        finally:
            reader.execute("ROLLBACK")
            request.join(30)
        assert not request.is_alive()
        assert "Accept your invitation" in sent_mail.read_text()


@pytest.mark.parametrize("api", [EMAIL], indirect=True)
def test_email_failure_is_reported_and_the_invitation_is_kept(failing_mail, api) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        session, identity_id = _session_and_identity(api, tmpdir)

        with pytest.raises(pfc.exceptions.UI, match="invitation was created but its email could not be sent"):
            session.invite_identity(identity_id, "email")

        # The response says the invitation exists: it must be in the audit log.
        created = [
            e
            for e in session.list_audit_log().entries
            if e.type == "identity-invitation-create" and e.details["identity_id"] == identity_id
        ]
        assert len(created) == 1
