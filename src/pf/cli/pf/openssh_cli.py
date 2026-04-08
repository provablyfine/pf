import base64
import os

from ... import client, jwk, ssh


def _user_trusted_keys_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    response = api.no_auth.get(f"{api.directory.ssh}/user/trusted-keys")
    if response.status_code != 200:
        raise client.exceptions.UI(response.json()["title"])
    print(response.text)


def _sign_host_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)

    public_keys = []
    filename_from_fingerprint = {}
    for filename in args.public_key:
        with open(filename, "rb") as f:
            key = f.read()
            public_key = jwk.Public.from_openssh(key)
            public_keys.append(public_key.to_dict())
            filename_from_fingerprint[public_key.ssh_fingerprint()] = filename

    cert_response = auth.post(f"{auth.directory.ssh}/host/certificate", json={"public_keys": public_keys})
    if cert_response.status_code != 200:
        raise client.exceptions.UI(cert_response.json()["title"])
    for certificate in cert_response.json()["certificates"]:
        openssh_certificate = base64.b64decode(certificate)
        cert = ssh.cert.Cert.from_openssh(openssh_certificate)
        public_key_filename = filename_from_fingerprint[cert.public_key.ssh_fingerprint()]
        cert_filename = f"{public_key_filename.rstrip('.pub')}.cert"
        fd = os.open(cert_filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with open(fd, "wb+") as f:
            f.write(openssh_certificate + b"\n")


def _authorized_principals(args):
    with open(args.host_certificate, "rb") as f:
        data = f.read()
        host_certificate = ssh.cert.Cert.from_openssh(data)
        host_items = host_certificate.identifier.split(":")
        if len(host_items) == 0:
            raise client.exceptions.UI(f"Invalid host identifier={host_certificate.identifier}")
        host_identifier = host_items[0]

    certificate = base64.b64decode(args.certificate.encode("ascii"))
    cert = ssh.serde.deserialize_cert(certificate)
    accepted = []
    for principal in cert.principals:
        items = principal.split("@")
        if len(items) != 2:
            raise client.exceptions.UI(f"Invalid user principal={principal}")
        username, host_id = items
        if username != args.username:
            # the certificate grants access to a username that is not the user that is currently
            # requested by the SSH connection
            continue
        if host_id != host_identifier:
            raise client.exceptions.UI(f"Invalid user host id={host_id} expected={host_identifier}")
        accepted.append(principal)
    print("\n".join(accepted))


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True, dest="_cmd2")

    sign_host_parser = subparsers.add_parser("sign-host")
    sign_host_parser.add_argument("--public-key", action="append", default=[], help="Public key to sign")
    sign_host_parser.set_defaults(func=_sign_host_function)

    user_trusted_keys_parser = subparsers.add_parser("user-trusted-keys")
    user_trusted_keys_parser.set_defaults(func=_user_trusted_keys_function)

    authorized_principals_parser = subparsers.add_parser("authorized-principals")
    authorized_principals_parser.add_argument(
        "--host-certificate", help="One of the signed host certificates", default="/etc/sshd/ssh_host_ed25519_key.cert"
    )
    authorized_principals_parser.add_argument("--username", required=True)
    authorized_principals_parser.add_argument("--certificate", help="base64 user certificate to parse", required=True)
    authorized_principals_parser.set_defaults(func=_authorized_principals)
