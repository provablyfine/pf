"""Certificate serial numbers are never reused, whichever kind of certificate is signed."""

import base64

import provablyfine_client as pfc

import provablyfine.jwk
import provablyfine.ssh.cert
import tests.test_identity_self_token


def _serials(certificates: list[str]) -> list[int]:
    return [provablyfine.ssh.cert.Cert.from_openssh(base64.b64decode(c)).serial_number for c in certificates]


def _public_key() -> dict[str, object]:
    return provablyfine.jwk.Private.generate_ed25519().public().to_dict()


def test_host_certificates_never_reuse_a_serial(api, tmp_path) -> None:
    factory, _name, _role_id = tests.test_identity_self_token._setup_session(api.port, tmp_path)
    sc = factory.session()

    first = _serials(sc.sign_host_certificates([_public_key() for _ in range(3)]).certificates)
    second = _serials(sc.sign_host_certificates([_public_key() for _ in range(2)]).certificates)

    assert len(first + second) == 5
    assert len(set(first + second)) == 5


def test_user_certificates_never_reuse_a_serial(api, tmp_path) -> None:
    factory, identity_name, role_id = tests.test_identity_self_token._setup_session(api.port, tmp_path)
    sc: pfc.SessionClient = factory.session()
    tests.test_identity_self_token._grant_shell(sc, role_id, identity_name, max_session_ttl_s=None)

    def sign() -> list[int]:
        response = sc.get_user_certificate(
            hostname=identity_name, username="root", action="shell", public_key=_public_key()
        )
        return _serials(response.certificates)

    serials = sign() + sign() + sign()
    assert len(set(serials)) == 3


def test_serial_counters_move_forward_for_host_and_user_certificates(api, tmp_path) -> None:
    """Host and user certificates are signed by different keys, so each kind counts on its own.

    What matters is that the counter of each key moves forward.
    """
    factory, identity_name, role_id = tests.test_identity_self_token._setup_session(api.port, tmp_path)
    sc = factory.session()
    tests.test_identity_self_token._grant_shell(sc, role_id, identity_name, max_session_ttl_s=None)

    host = _serials(sc.sign_host_certificates([_public_key()]).certificates)[0]
    user = _serials(
        sc.get_user_certificate(
            hostname=identity_name, username="root", action="shell", public_key=_public_key()
        ).certificates
    )[0]
    host_again = _serials(sc.sign_host_certificates([_public_key()]).certificates)[0]
    user_again = _serials(
        sc.get_user_certificate(
            hostname=identity_name, username="root", action="shell", public_key=_public_key()
        ).certificates
    )[0]

    assert host_again > host
    assert user_again > user
