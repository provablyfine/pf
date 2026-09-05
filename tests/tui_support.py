import os
import subprocess

import textual.worker

import provablyfine.client


async def _wait(pilot, app=None):
    """Wait for pending events then all workers to complete.

    Structure:
    1. pilot.pause() — drain event loop, let message handlers run
    2. wait_for_complete() — wait for @work-decorated methods (save/add/delete)
    3. pilot.pause() — let UI re-render after worker result (notifications, updates)
    """
    await pilot.pause()  # let pending events dispatch and workers start
    target = app if app is not None else pilot.app
    try:
        await target.workers.wait_for_complete()  # wait for save/add/delete
    except (textual.worker.WorkerFailed, textual.worker.WorkerCancelled):
        pass  # errors already handled by app._handle_exception → notify()
    await pilot.pause()  # let UI re-render (notifications, table updates)


def _run(args: list[str], env: dict[str, str]):
    return subprocess.run(args, env=env, check=True, capture_output=True)


def _setup_ssh_auth_sock(ssh_agent):
    """Set up SSH_AUTH_SOCK for the test. Returns a context manager."""

    class SshAuthSockContext:
        def __enter__(self):
            self.old_ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")
            os.environ["SSH_AUTH_SOCK"] = ssh_agent.socket

        def __exit__(self, *args):
            if self.old_ssh_auth_sock is None:
                os.environ.pop("SSH_AUTH_SOCK", None)
            else:
                os.environ["SSH_AUTH_SOCK"] = self.old_ssh_auth_sock

    return SshAuthSockContext()


def _setup(api, tmpdir):
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
    env = {**os.environ, "PATH": f"{scripts}:{os.environ['PATH']}"}
    directory_url = f"http://127.0.0.1:{api.port}/pf/t/root/directory"
    config_file = os.path.join(tmpdir, "config.json")

    account_key = os.path.join(tmpdir, "account")
    _run(["ssh-keygen", "-t", "ed25519", "-f", account_key, "-N", ""], env)
    _run(["pfa", "-c", config_file, "initialize", directory_url, f"--key={account_key}"], env)

    session_key = os.path.join(tmpdir, "session")
    _run(["ssh-keygen", "-t", "ed25519", "-f", session_key, "-N", ""], env)
    _run(["pfa", "-c", config_file, "login", f"--session-key={session_key}"], env)

    cfg = provablyfine.client.Config.load(config_file)
    return provablyfine.client.Factory(cfg).async_session()


def _seed_named_identities(api, tmpdir, names: list[str]) -> None:
    """Create additional named identities via the pfa CLI, for tour recordings
    that browse pre-existing data instead of creating their own."""
    scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
    env = {**os.environ, "PATH": f"{scripts}:{os.environ['PATH']}"}
    config_file = os.path.join(tmpdir, "config.json")
    for name in names:
        _run(["pfa", "-c", config_file, "identity", "create", "-n", name], env)
