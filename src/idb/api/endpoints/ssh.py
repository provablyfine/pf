from ... import wa

from .. import signature


@signature.verify_session
def sign_user_certificate(request: wa.Request) -> wa.Response:
    certificate = b'aa'
    return wa.Response(
        status_code=200,
        headers={
            'Content-Type': 'application/octet-stream',
        },
        body=certificate,
    )
