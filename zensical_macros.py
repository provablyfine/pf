import tomllib


def define_env(env):
    with open("pyproject.toml", "rb") as f:
        config = tomllib.load(f)
    env.variables["pf_version"] = config["project"]["version"]
