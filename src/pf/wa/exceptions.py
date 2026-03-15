class HTTPException(BaseException):
    def __init__(self, response):
        self._response = response

    @property
    def response(self):
        return self._response
