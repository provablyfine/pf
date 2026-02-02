import datetime
import tabulate

from .. import ssh
from . import ssh_utils

@ssh_utils.exception
def _read_function(args):
    with open(args.filename, 'rb') as f:
        data = f.read()
    cert = ssh.cert.Cert.from_base64(data)
    match cert.role:
        case ssh.cert.Role.HOST:
            role = 'host'
        case ssh.cert.Role.USER:
            role = 'user'
        case _:
            assert False

    rows = [
        ('validity_period', 'ok' if cert.is_valid() else 'ko'),
        ('is_signature_valid', 'yes' if cert.is_signature_valid else 'no'),
        ('key_type', cert.key_type),
        ('serial_number', cert.serial_number),
        ('role', role),
        ('identifier', cert.identifier),
    ]
    for principal in cert.principals:
        rows.append(('principal', principal))
    if cert.valid_after == 0:
        valid_after = 'always'
    else:
        valid_after = datetime.datetime.fromtimestamp(cert.valid_after).strftime('%Y-%m-%s %H:%M:%S')
    if cert.valid_before == 0xffffffffffffffff:
        valid_before = 'forever'
    else:
        valid_before = datetime.datetime.fromtimestamp(cert.valid_before).strftime('%Y-%m-%s %H:%M:%S')
    rows += [
        ('valid_after', valid_after),
        ('valid_before', valid_before),
    ]
    if cert.critical_options.force_command:
        rows.append(('force-command', cert.critical_options.force_command))
    if cert.critical_options.source_address:
        for address in cert.critical_options.source_address:
            rows.append(('source-address', address))
    if cert.critical_options.verify_required:
        rows.append(('verify-required', 'yes'))
    if cert.extensions.no_touch_required:
        rows.append(('no-touch-required', 'yes'))
    if cert.extensions.permit_agent_forwarding:
        rows.append(('permit-agent-forwarding', 'yes'))
    if cert.extensions.permit_pty:
        rows.append(('permit-pty', 'yes'))
    if cert.extensions.permit_user_rc:
        rows.append(('permit-user-rc', 'yes'))
    if cert.extensions.permit_x11_forwarding:
        rows.append(('permit-x11-forwarding', 'yes'))

    print(tabulate.tabulate(rows))


def _sign_host_function(args):
    pass


def add_subparsers(parser):
    subparsers = parser.add_subparsers(required=True)

    read_parser = subparsers.add_parser('read', help='Read certificate')
    read_parser.add_argument('filename')
    read_parser.set_defaults(func=_read_function)

    sign_host_parser = subparsers.add_parser('sign-host', help='Generate host certificate')
    sign_host_parser.add_argument('--key', help='Public key to generate a certificate for', required=True)
    sign_host_parser.add_argument('--with', help='Private key to sign the certificate with', required=True)
    sign_host_parser.add_argument('-i', '--identifier', help='Identifier of this host. If unspecified, ssh fingerprint of the public key.')
    sign_host_parser.add_argument('-p', '--principal', help='Which principal this certificate will be valid for. Typically, the host FQDN.', required=True, nargs='+', default=[])
    sign_host_parser.add_argument('--valid-after', help='If specified, the certificate will be valid only after this date')
    sign_host_parser.add_argument('--valid-before', help='If specified, the certificate will be valid only before this date')
    sign_host_parser.set_defaults(func=_sign_host_function)
