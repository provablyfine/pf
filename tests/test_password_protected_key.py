import pathlib
import shutil

import pytest

from . import utils


def test_password_protected_key_read(api):
    utils.run_cram(
        "tests/password-protected-key-read.t",
        {"API_PORT": str(api.port)},
    )


@pytest.mark.skipif(not shutil.which("ssh-agent"), reason="ssh-agent not found")
def test_password_protected_key_create(api, ssh_agent, tmp_path: pathlib.Path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    utils.run_cram(
        "tests/password-protected-key-create.t",
        {
            "API_PORT": str(api.port),
            "HOME": str(home),
            "SSH_AUTH_SOCK": ssh_agent.socket,
        },
    )
