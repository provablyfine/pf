import argparse
import json

import tabulate

from ... import client


def _auth_list_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
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
                rows.append([a["id"], a["name"], a["config"]["type"], a["is_enabled"], a["description"]])
            if rows:
                output = tabulate.tabulate(rows, headers=["id", "name", "type", "enabled", "description"])
            else:
                output = ""
        case _:
            assert False, args.format
    if output:
        print(output)


def _auth_create_http_sig_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)
    body: dict = {
        "name": args.name,
        "description": args.description or "",
        "config": {
            "type": "http_sig",
        },
        "tags": [{"name": t.split("=", 1)[0], "value": t.split("=", 1)[1]} for t in (args.tag or [])],
    }
    response = auth.post(auth.directory.auth, json=body)
    if response.status_code != 201:
        raise client.exceptions.UI(f"Unable to create auth config. {response.json()['title']}")


def _auth_create_oidc_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)
    body: dict = {
        "name": args.name,
        "description": args.description or "",
        "tags": [{"name": t.split("=", 1)[0], "value": t.split("=", 1)[1]} for t in (args.tag or [])],
        "config": {
            "type": "oidc",
            "issuer": args.issuer,
            "client_id": args.client_id,
        },
    }
    if args.client_secret:
        body["config"]["client_secret"] = args.client_secret
    response = auth.post(auth.directory.auth, json=body)
    if response.status_code != 201:
        raise client.exceptions.UI(f"Unable to create auth config. {response.json()['title']}")


def _auth_create_oauth2_github_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)
    body: dict = {
        "name": args.name,
        "description": args.description or "",
        "tags": [{"name": t.split("=", 1)[0], "value": t.split("=", 1)[1]} for t in (args.tag or [])],
        "config": {
            "type": "oauth2-github",
            "client_id": args.client_id,
            "client_secret": args.client_secret,
        },
    }
    response = auth.post(auth.directory.auth, json=body)
    if response.status_code != 201:
        raise client.exceptions.UI(f"Unable to create auth config. {response.json()['title']}")


def _auth_read_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
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
                ["type", a["config"]["type"]],
                ["description", a["description"]],
                ["enabled", a["is_enabled"]],
                ["created_at", a["created_at"]],
                ["tags", " ".join(f"{t['name']}={t['value']}" for t in a.get("tags", []))],
            ]
            if a["config"]["type"] == "oidc":
                params = a.get("config", {})
                rows.append(["issuer", params.get("issuer", "")])
                rows.append(["client_id", params.get("client_id", "")])
                rows.append(["callback_url", params.get("callback_url", "")])
                if params.get("client_secret"):
                    rows.append(["client_secret", params.get("client_secret", "")])
            elif a["config"]["type"] == "oauth2-github":
                params = a.get("config", {})
                rows.append(["authorization_endpoint", params.get("authorization_endpoint", "")])
                rows.append(["client_id", params.get("client_id", "")])
                rows.append(["callback_url", params.get("callback_url", "")])
            print(tabulate.tabulate(rows, tablefmt="plain"))
        case _:
            assert False, args.format


def _auth_update_function(args: argparse.Namespace) -> None:
    body: dict = {}
    if args.name is not None:
        body["name"] = args.name
    if args.description is not None:
        body["description"] = args.description
    if args.enable:
        body["is_enabled"] = True
    if args.disable:
        body["is_enabled"] = False
    if not body:
        raise client.exceptions.UI("Nothing to update")
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)
    response = auth.patch(f"{auth.directory.auth}/{args.id}", json=body)
    if response.status_code == 404:
        raise client.exceptions.UI("Auth config not found")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to update auth config. {response.json().get('title', '')}")


def _auth_delete_function(args: argparse.Namespace) -> None:
    c = client.Config.load(args.config)
    api = client.Client(c, timeout=args.timeout)
    auth = api.session_auth(c.session_key)
    response = auth.delete(f"{auth.directory.auth}/{args.id}")
    if response.status_code == 404:
        raise client.exceptions.UI("Auth config not found")
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to delete auth config. {response.json().get('title', '')}")


def add_subparser(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(required=True, dest="_cmd2")

    list_parser = subparsers.add_parser("list", help="List auth configs")
    list_parser.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    list_parser.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text")
    list_parser.set_defaults(func=_auth_list_function)

    create_parser = subparsers.add_parser("create", help="Create an auth config")
    create_type_subparsers = create_parser.add_subparsers(required=True, dest="_cmd3")

    create_http_sig_parser = create_type_subparsers.add_parser("http_sig", help="HTTP signature auth")
    create_http_sig_parser.add_argument("-n", "--name", required=True, help="Name of auth config")
    create_http_sig_parser.add_argument("--description", help="Description")
    create_http_sig_parser.add_argument("--tag", action="append", dest="tag", help="Tag name=value (repeatable)")
    create_http_sig_parser.set_defaults(func=_auth_create_http_sig_function)

    create_oidc_parser = create_type_subparsers.add_parser("oidc", help="OpenID Connect auth")
    create_oidc_parser.add_argument("-n", "--name", required=True, help="Name of auth config")
    create_oidc_parser.add_argument("--description", help="Description")
    create_oidc_parser.add_argument("--tag", action="append", dest="tag", help="Tag name=value (repeatable)")
    create_oidc_parser.add_argument("--issuer", required=True, help="OIDC issuer URL")
    create_oidc_parser.add_argument("--client-id", required=True, help="OIDC client ID")
    create_oidc_parser.add_argument("--client-secret", help="OIDC client secret (for providers that require it)")
    create_oidc_parser.set_defaults(func=_auth_create_oidc_function)

    create_oauth2_github_parser = create_type_subparsers.add_parser("oauth2-github", help="GitHub OAuth2 auth")
    create_oauth2_github_parser.add_argument("-n", "--name", required=True, help="Name of auth config")
    create_oauth2_github_parser.add_argument("--description", help="Description")
    create_oauth2_github_parser.add_argument("--tag", action="append", dest="tag", help="Tag name=value (repeatable)")
    create_oauth2_github_parser.add_argument("--client-id", required=True, help="GitHub OAuth2 client ID")
    create_oauth2_github_parser.add_argument("--client-secret", required=True, help="GitHub OAuth2 client secret")
    create_oauth2_github_parser.set_defaults(func=_auth_create_oauth2_github_function)

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
