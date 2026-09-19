import pathlib

import provablyfine_client as pfc
import pytest

import provablyfine.client
import provablyfine.jwk


def _login(
    sc: provablyfine.client.Factory, account_key_file: pathlib.Path
) -> tuple[pfc.SessionClient, provablyfine.jwk.Private]:
    """Log in with a fresh session key. Each call creates one more session for the same identity."""
    session_key = provablyfine.jwk.Private.generate_ed25519()
    session_key_file = account_key_file.parent / f"session_key_{session_key.public().thumbprint()}"
    session_key_file.write_bytes(session_key.to_pem())
    result = sc.account(str(account_key_file), str(session_key_file)).login_http_sig(session_key.public().to_dict())
    client = sc.session_with_private_key(session_key)
    if result.roles:
        client.update_session(result.roles[0].id)
    return client, session_key


def test_logout_ends_only_the_calling_session(api, tmp_path: pathlib.Path) -> None:
    account_key_file = tmp_path / "account_key"
    account_key_file.write_bytes(provablyfine.jwk.Private.generate_ed25519().to_pem())
    config = provablyfine.client.Config(
        directory_url=f"http://127.0.0.1:{api.port}/pf/t/root/directory",
        account_key_file=str(account_key_file),
    )
    sc = provablyfine.client.Factory(config)
    sc.invitation(sc.public().initialize(), str(account_key_file)).accept_invitation()

    first, _ = _login(sc, account_key_file)
    second, _ = _login(sc, account_key_file)
    first.ping()

    first.logout()

    with pytest.raises(pfc.exceptions.SessionExpired, match="logged out"):
        first.ping()
    # Nothing can be done with a session that has ended, including logging out again.
    with pytest.raises(pfc.exceptions.SessionExpired, match="logged out"):
        first.logout()
    # Another session of the same identity is unaffected.
    second.ping()
    # The identity can log in again.
    third, _ = _login(sc, account_key_file)
    third.ping()
