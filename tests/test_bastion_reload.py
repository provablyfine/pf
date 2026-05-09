from . import utils


def test_bastion_reload(api, ssh_agent, bastion_server):
    """Test bastion snapshot/restore cycle via control socket."""
    utils.run_cram(
        "tests/bastion_reload.t",
        {
            "API_PORT": str(api.port),
            "SSH_AUTH_SOCK": ssh_agent.socket,
            "BASTION_PORT": str(bastion_server.port),
            "BASTION_CTRL_SOCK": bastion_server.control_socket,
        },
    )
