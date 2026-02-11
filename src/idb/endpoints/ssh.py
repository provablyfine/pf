from .. import signature
from .. import wa


@signature.verify_session
def sign_user_certificate(request: wa.Request) -> wa.Response:
    certificate = b''
    return wa.Response(
        status_code=200,
        headers={
            'Content-Type': 'application/octet-stream',
        },
        body=certificate,
    )
