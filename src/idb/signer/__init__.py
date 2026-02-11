from . import config
from . import app

def load_config(filename):
    return config.Config.load(filename)

def create_app(conf):
    return app.create(conf)
