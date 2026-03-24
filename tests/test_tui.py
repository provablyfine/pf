import os
import subprocess
import tempfile

import pytest

import pf.client
import pf.tui.app
import pf.tui.async_client


def _run(args, env, **kwargs):
    return subprocess.run(args, env=env, check=True, capture_output=True, **kwargs)


def _setup(api, tmpdir):
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
    env = {**os.environ, "PATH": f"{scripts}:{os.environ['PATH']}"}
    directory_url = f"http://127.0.0.1:{api.port}/pf/t/root/directory"
    config_file = os.path.join(tmpdir, "config.json")

    _run(["pf", "-c", config_file, "config", "--directory", directory_url], env)
    result = _run(["pfa", "-c", config_file, "initialize"], env, text=True)
    invitation = result.stdout.strip()

    account_key = os.path.join(tmpdir, "account")
    _run(["ssh-keygen", "-t", "ed25519", "-f", account_key, "-N", ""], env)
    _run(["pf", "-c", config_file, "accept", f"--invitation={invitation}", f"--key={account_key}"], env)

    session_key = os.path.join(tmpdir, "session")
    _run(["ssh-keygen", "-t", "ed25519", "-f", session_key, "-N", ""], env)
    _run(["pf", "-c", config_file, "login", f"--session-key={session_key}"], env)

    cfg = pf.client.Config.load(config_file)
    http_client = pf.client.Client(cfg).session_auth(cfg.session_key)
    return pf.tui.async_client.AsyncClient(http_client)


@pytest.mark.anyio
async def test_tui_grant_edit_identity_fails(api):
    """Editing an identity grant on the root role must fail with an error notification.

    The default user is a member of the root role (the very role being edited),
    so the API rejects the PATCH and the TUI shows an error notification.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        auth = _setup(api, tmpdir)
        app = pf.tui.app.TuiApp(auth)

        async with app.run_test(size=(200, 50)) as pilot:
            # Wait for the role list to load
            await pilot.pause(1.0)

            # Root role is the only role and the cursor is on it; press 'g' to view grants
            await pilot.press("g")
            await pilot.pause(0.5)

            # The identity grant is the first row (row 0)
            # Press 'e' to open the edit screen
            await pilot.press("e")

            # Wait for the GrantEditScreen and IdentityGrantEditWidget.on_mount
            # (three API calls: identities, tags, boundaries)
            await pilot.pause(3.0)

            # Save without changes
            await pilot.press("ctrl+s")

            # Wait for the PATCH response and notification
            await pilot.pause(2.0)

        error_notifications = [
            n for n in app._notifications if n.severity == "error"
        ]
        assert error_notifications, "Expected an error notification after saving identity grant"
