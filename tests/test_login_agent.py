from . import utils


def test_login_agent(api):
    utils.run_cram(
        "tests/login_agent.t",
        {"API_PORT": str(api.port)},
    )
