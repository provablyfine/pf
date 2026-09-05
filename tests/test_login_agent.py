from . import utils


def test_login_agent(api):
    """`pf login` with no --session-key: the session key is generated and
    kept alive by the peer-credential oracle (browser_login.generate_session_key()),
    not pushed into a real ssh-agent -- see login_agent.t.
    """
    utils.run_cram(
        "tests/login_agent.t",
        {"API_PORT": str(api.port)},
    )
