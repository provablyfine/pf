import argparse
import json

import provablyfine_client as pfc
import tabulate

from ... import client


def _auth_list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    response = sc.list_auths()
    auths = response.auths
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(a.id) for a in auths)
        case "json":
            output = json.dumps([a.model_dump() for a in auths], indent=2)
        case "text":
            rows: list[list[int | str | bool]] = []
            for a in auths:
                rows.append([a.id, a.name, a.client_type, a.config.type, a.is_enabled, a.description])
            if rows:
                output = tabulate.tabulate(
                    rows, headers=["id", "name", "client_type", "type", "enabled", "description"]
                )
            else:
                output = ""
        case _:
            assert False, args.format
    if output:
        print(output)


def _auth_create_http_sig_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.create_auth_http_sig(args.name, args.client_type, args.description or "")


def _auth_create_oidc_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.create_auth_oidc(
        args.name, args.client_type, args.description or "", args.issuer, args.client_id, args.client_secret
    )


def _auth_create_oidc_device_code_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.create_auth_oidc_device_code(
        args.name, args.client_type, args.description or "", args.issuer, args.client_id, args.client_secret
    )


def _auth_read_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    a = sc.get_auth(args.id)
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            print(a.id)
        case "json":
            print(json.dumps(a.model_dump(), indent=2))
        case "text":
            rows: list[list[int | str | bool]] = [
                ["id", a.id],
                ["name", a.name],
                ["client_type", a.client_type],
                ["type", a.config.type],
                ["description", a.description],
                ["enabled", a.is_enabled],
                ["created_at", a.created_at],
            ]
            if isinstance(a.config, pfc.schemas.OidcConfig):
                rows.append(["issuer", a.config.issuer])
                rows.append(["client_id", a.config.client_id])
                rows.append(["callback_url", a.config.callback_url])
                if a.config.client_secret:
                    rows.append(["client_secret", a.config.client_secret])
            elif isinstance(a.config, pfc.schemas.OidcDeviceCodeConfig):
                rows.append(["issuer", a.config.issuer])
                rows.append(["client_id", a.config.client_id])
                if a.config.client_secret:
                    rows.append(["client_secret", a.config.client_secret])
            print(tabulate.tabulate(rows, tablefmt="plain"))
        case _:
            assert False, args.format


def _auth_update_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    is_enabled = None
    if args.enable:
        is_enabled = True
    elif args.disable:
        is_enabled = False
    sc.update_auth(args.id, name=args.name, description=args.description, is_enabled=is_enabled)


def _auth_delete_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    sc = client.Factory(c, timeout=args.timeout).session()
    sc.delete_auth(args.id)


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="subcommand", metavar="subcommand")

    list_parser = subparsers.add_parser("list", help="List auth configs")
    list_parser.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    list_parser.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text")
    list_parser.set_defaults(func=_auth_list_function)

    create_parser = subparsers.add_parser("create", help="Create an auth config")
    create_type_subparsers = create_parser.add_subparsers(required=True, dest="subsubcommand", metavar="subsubcommand")

    create_http_sig_parser = create_type_subparsers.add_parser("http_sig", help="HTTP signature auth")
    create_http_sig_parser.add_argument("-n", "--name", required=True, help="Name of auth config")
    create_http_sig_parser.add_argument("--client-type", required=True, choices=["cli", "web"], help="Client type")
    create_http_sig_parser.add_argument("--description", help="Description")
    create_http_sig_parser.set_defaults(func=_auth_create_http_sig_function)

    create_oidc_parser = create_type_subparsers.add_parser("oidc", help="OpenID Connect auth")
    create_oidc_parser.add_argument("-n", "--name", required=True, help="Name of auth config")
    create_oidc_parser.add_argument("--client-type", required=True, choices=["cli", "web"], help="Client type")
    create_oidc_parser.add_argument("--description", help="Description")
    create_oidc_parser.add_argument("--issuer", required=True, help="OIDC issuer URL")
    create_oidc_parser.add_argument("--client-id", required=True, help="OIDC client ID")
    create_oidc_parser.add_argument("--client-secret", help="OIDC client secret (for providers that require it)")
    create_oidc_parser.set_defaults(func=_auth_create_oidc_function)

    create_oidc_dc_parser = create_type_subparsers.add_parser(
        "oidc-device-code", help="OpenID Connect device code auth"
    )
    create_oidc_dc_parser.add_argument("-n", "--name", required=True, help="Name of auth config")
    create_oidc_dc_parser.add_argument("--client-type", required=True, choices=["cli", "web"], help="Client type")
    create_oidc_dc_parser.add_argument("--description", help="Description")
    create_oidc_dc_parser.add_argument("--issuer", required=True, help="OIDC issuer URL")
    create_oidc_dc_parser.add_argument("--client-id", required=True, help="OIDC client ID")
    create_oidc_dc_parser.add_argument("--client-secret", help="OIDC client secret (for providers that require it)")
    create_oidc_dc_parser.set_defaults(func=_auth_create_oidc_device_code_function)

    read_parser = subparsers.add_parser("read", help="Read an auth config")
    read_parser.add_argument("-i", "--id", type=int, required=True, help="ID of auth config")
    read_parser.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    read_parser.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text")
    read_parser.set_defaults(func=_auth_read_function)

    update_parser = subparsers.add_parser("update", help="Update an auth config")
    update_parser.add_argument("-i", "--id", type=int, required=True, help="ID of auth config")
    update_parser.add_argument("-n", "--name", help="New name")
    update_parser.add_argument("--description", help="New description")
    eg = update_parser.add_mutually_exclusive_group()
    eg.add_argument("--enable", action="store_true", default=False, help="Enable auth config")
    eg.add_argument("--disable", action="store_true", default=False, help="Disable auth config")
    update_parser.set_defaults(func=_auth_update_function)

    delete_parser = subparsers.add_parser("delete", help="Delete an auth config")
    delete_parser.add_argument("-i", "--id", type=int, required=True, help="ID of auth config")
    delete_parser.set_defaults(func=_auth_delete_function)
