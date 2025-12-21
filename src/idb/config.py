import starlette.config


config = starlette.config.Config()
DEBUG = config('DEBUG', cast=bool, default=False)
BASE_URL = config('BASE_URL', default='http://127.0.0.1:8000')
DATABASE_URL = config('DATABASE_URL', default='sqlite:///admin.db')
KEK_FILENAME = config('KEK_FILENAME', default='kek.key')
