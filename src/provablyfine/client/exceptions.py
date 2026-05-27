class UI(Exception):
    pass


class Forbidden(UI):
    pass


class KeyExpired(Exception):
    def __init__(self, key_type: str):
        self.key_type = key_type
