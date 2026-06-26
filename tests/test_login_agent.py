import shutil

import pytest

from . import utils


@pytest.mark.skipif(not shutil.which("ssh-agent"), reason="ssh-agent not found")
def test_login_agent(api, ssh_agent):
    utils.run_cram(
        "tests/login_agent.t",
        {
            "API_PORT": str(api.port),
            "SSH_AUTH_SOCK": ssh_agent.socket,
        },
    )
