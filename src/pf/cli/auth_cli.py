import json

import tabulate

from .. import client


def _auth_list_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.get(auth.directory.auth)
    if response.status_code != 200:
        raise client.exceptions.UI("Unable to list auth configs")
    auths = response.json()["auths"]
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(a["id"]) for a in auths)
        case "json":
            output = json.dumps(auths, indent=2)
        case "text":
            rows = []
            for a in auths:
                rows.append([a["id"], a["name"], a["type"], a["is_enabled"], a["description"]])
            if rows:
                output = tabulate.tabulate(rows, headers=["id", "name", "type", "enabled", "description"])
            else:
                output = ""
        case _:
            assert False, args.format
    if output:
        print(output)


def _auth_create_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    body: dict = {
        "name": args.name,
        "description": args.description or "",
        "type": args.type,
        "tag_id_list": args.tag_id or [],
    }
    if args.type == "oidc":
        if not args.issuer or not args.client_id:
            raise client.exceptions.UI("--issuer and --client-id are required for type oidc")
        oidc_params: dict = {"issuer": args.issuer, "client_id": args.client_id}
        if args.client_secret:
            oidc_params["client_secret"] = args.client_secret
        body["oidc_params"] = oidc_params
    response = auth.post(auth.directory.auth, json=body)
    if response.status_code != 201:
        raise client.exceptions.UI(f"Unable to create auth config. {response.json()['title']}")


def _auth_read_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.get(f"{auth.directory.auth}/{args.id}")
    if response.status_code == 404:
        raise client.exceptions.UI("Auth config not found")
    if response.status_code != 200:
        raise client.exceptions.UI("Unable to read auth config")
    a = response.json()
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            print(a["id"])
        case "json":
            print(json.dumps(a, indent=2))
        case "text":
            rows = [
                ["id", a["id"]],
                ["name", a["name"]],
                ["type", a["type"]],
                ["description", a["description"]],
                ["enabled", a["is_enabled"]],
                ["created_at", a["created_at"]],
                ["tag_id_list", ", ".join(str(t) for t in a.get("tag_id_list", []))],
            ]
            if a["type"] == "oidc":
                params = a.get("params", {})
                rows.append(["issuer", params.get("issuer", "")])
                rows.append(["client_id", params.get("client_id", "")])
                if params.get("client_secret"):
                    rows.append(["client_secret", params.get("client_secret", "")])
            print(tabulate.tabulate(rows, tablefmt="plain"))
        case _:
            assert False, args.format


def _auth_update_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    body: dict = {}
    if args.name is not None:
        body["name"] = args.name
    if args.description is not None:
        body["description"] = args.description
    if args.enable:
        body["is_enabled"] = True
    if args.disable:
        body["is_enabled"] = False
    if args.issuer is not None or args.client_id is not None or args.client_secret is not None:
        oidc_params: dict = {}
        if args.issuer is not None:
            oidc_params["issuer"] = args.issuer
        if args.client_id is not None:
            oidc_params["client_id"] = args.client_id
        if args.client_secret is not None:
            oidc_params["client_secret"] = args.client_secret
        body["oidc_params"] = oidc_params
    if not body:
        raise client.exceptions.UI("Nothing to update")
    response = auth.patch(f"{auth.directory.auth}/{args.id}", json=body)
    if response.status_code == 404:
        raise client.exceptions.UI("Auth config not found")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to update auth config. {response.json().get('title', '')}")


def _auth_delete_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.delete(f"{auth.directory.auth}/{args.id}")
    if response.status_code == 404:
        raise client.exceptions.UI("Auth config not found")
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to delete auth config. {response.json().get('title', '')}")


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser("list", help="List auth configs")
    list_parser.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    list_parser.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text")
    list_parser.set_defaults(func=_auth_list_function)

    create_parser = subparsers.add_parser("create", help="Create an auth config")
    create_parser.add_argument("-n", "--name", required=True, help="Name of auth config")
    create_parser.add_argument("--description", help="Description")
    create_parser.add_argument("--type", required=True, choices=["http_sig", "oidc"], help="Auth type")
    create_parser.add_argument("--tag-id", type=int, action="append", dest="tag_id", help="Tag ID (repeatable)")
    create_parser.add_argument("--issuer", help="OIDC issuer URL (required for type oidc)")
    create_parser.add_argument("--client-id", help="OIDC client ID (required for type oidc)")
    create_parser.add_argument("--client-secret", help="OIDC client secret (optional, for providers that require it)")
    create_parser.set_defaults(func=_auth_create_function)

    read_parser = subparsers.add_parser("read", help="Read an auth config")
    read_parser.add_argument("-i", "--id", type=int, required=True, help="ID of auth config")
    read_parser.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    read_parser.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text")
    read_parser.set_defaults(func=_auth_read_function)

    update_parser = subparsers.add_parser("update", help="Update an auth config")
    update_parser.add_argument("-i", "--id", type=int, required=True, help="ID of auth config")
    update_parser.add_argument("-n", "--name", help="New name")
    update_parser.add_argument("--description", help="New description")
    enable_group = update_parser.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", action="store_true", default=False, help="Enable auth config")
    enable_group.add_argument("--disable", action="store_true", default=False, help="Disable auth config")
    update_parser.add_argument("--issuer", help="New OIDC issuer URL")
    update_parser.add_argument("--client-id", help="New OIDC client ID")
    update_parser.add_argument("--client-secret", help="New OIDC client secret")
    update_parser.set_defaults(func=_auth_update_function)

    delete_parser = subparsers.add_parser("delete", help="Delete an auth config")
    delete_parser.add_argument("-i", "--id", type=int, required=True, help="ID of auth config")
    delete_parser.set_defaults(func=_auth_delete_function)
