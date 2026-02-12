from ... import wa

from .. import signature


@signature.verify_session
def sign_user_certificate(request: wa.Request) -> wa.Response:
    #request.app.state.user_keys.current
    #request.app.state.user_keys.staged
    certificate = b'aa'
    return wa.Response(
        status_code=200,
        headers={
            'Content-Type': 'application/octet-stream',
        },
        body=certificate,
    )
