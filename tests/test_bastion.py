from . import utils


def test_bastion(api, ssh_agent, bastion_server):
    utils.run_cram(
        "tests/bastion.t",
        {
            "API_PORT": str(api.port),
            "SSH_AUTH_SOCK": ssh_agent.socket,
            "BASTION_PORT": str(bastion_server.port),
        },
    )
