def _sign_host_key_function(args):
    pass


def _download_host_signing_key_function(args):
    pass


def _sign_user_key_function(args):
    pass


def _download_user_signing_key_function(args):
    pass


def _list_remotes_function(args):
    pass


def add_subparsers(parser):
    parser.add_argument('--session-key', help='key to use to sign requests to the remote', default='session.key')
    subparsers = parser.add_subparsers(required=True)

    sign_host_key_parser = subparsers.add_parser('sign-host-key', help='Request signing a host key and download the resulting certificate')
    sign_host_key_parser.add_argument('--public-key', help='path to public key for which a certificate should be generated')
    sign_host_key_parser.add_argument('-o', '--output', help='path where the certificate for the key should be written', default='/dev/stdout')
    sign_host_key_parser.set_defaults(func=_sign_host_key_function)

    download_host_signing_key_parser = subparsers.add_parser('download-host-signing-key', help='Download the host signing key')
    download_host_signing_key_parser.add_argument('-o', '--output', help='Path where the host signing key should be written', default='/dev/stdout')
    download_host_signing_key_parser.set_defaults(func=_download_host_signing_key_function)

    sign_user_key_parser = subparsers.add_parser('sign-user-key', help='Request signing a user key and download the resulting certificate')
    sign_user_key_parser.add_argument('--public-key', help='path to public key for which a certificate should be generated')
    sign_user_key_parser.add_argument('-o', '--output', help='path where the certificate for the key should be written', default='/dev/stdout')
    sign_user_key_parser.set_defaults(func=_sign_user_key_function)

    download_user_signing_key_parser = subparsers.add_parser('download-user-signing-key', help='Download the user signing key')
    download_user_signing_key_parser.add_argument('-o', '--output', help='Path where the user signing key should be written', default='/dev/stdout')
    download_user_signing_key_parser.set_defaults(func=_download_user_signing_key_function)

    list_remotes_parser = subparsers.add_parser('list-remotes', help='List all remotes the current identity is allowed to connect to')
    list_remotes_parser.set_defaults(func=_list_remotes_function)

    #login_parser = subparsers.add_argument('login')
    #login_parser.set_defaults(func=_login_function)
