import json

import tabulate

from .. import client


def _tenants(auth, id: int | None = None):
    params = {}
    if id is not None:
        params["id"] = id
    response = auth.get(auth.directory.tenant, params=params)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to list tenants: {response.text}")
    return response.json()["tenants"]


_SORT_KEYS = {
    "id": lambda t: t["id"],
    "name": lambda t: (t["name"], t["id"]),
}


def _list_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    tenants = sorted(_tenants(auth), key=_SORT_KEYS[args.sort])
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(t["id"]) for t in tenants)
        case "json":
            output = json.dumps(tenants, indent=2)
        case "text":
            output = tabulate.tabulate(tenants, headers="keys") if tenants else ""
        case _:
            assert False
    if output:
        print(output)


def _get_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.get(f"{auth.directory.tenant}/{args.id}")
    if response.status_code == 404:
        raise client.exceptions.UI(f"Tenant {args.id} not found")
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to get tenant: {response.text}")
    t = response.json()
    print(tabulate.tabulate([t], headers="keys"))


def _create_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.post(auth.directory.tenant, json={"name": args.name, "display_name": args.display_name})
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to create tenant: {response.text}")
    t = response.json()
    print(tabulate.tabulate([t], headers="keys"))


def _update_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    data = {}
    if args.display_name is not None:
        data["display_name"] = args.display_name
    if args.enable:
        data["is_enabled"] = True
    elif args.disable:
        data["is_enabled"] = False
    if not data:
        raise client.exceptions.UI("Nothing to update")
    response = auth.patch(f"{auth.directory.tenant}/{args.id}", json=data)
    if response.status_code == 404:
        raise client.exceptions.UI(f"Tenant {args.id} not found")
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to update tenant: {response.text}")


def _delete_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.delete(f"{auth.directory.tenant}/{args.id}")
    if response.status_code == 404:
        raise client.exceptions.UI(f"Tenant {args.id} not found")
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to delete tenant: {response.text}")


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser("list", help="List tenants")
    list_parser.add_argument("-q", "--quiet", action="store_true", help="Equivalent to -f quiet")
    list_parser.add_argument(
        "-s", "--sort", choices=["id", "name"], default="id", help="Sort criterion. Default: %(default)s"
    )
    list_parser.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=_list_function)

    get_parser = subparsers.add_parser("get", help="Get a tenant")
    get_parser.add_argument("-i", "--id", type=int, required=True)
    get_parser.set_defaults(func=_get_function)

    create_parser = subparsers.add_parser("create", help="Create a tenant")
    create_parser.add_argument("--name", required=True, help="Tenant slug name")
    create_parser.add_argument("--display-name", required=True, dest="display_name", help="Tenant display name")
    create_parser.set_defaults(func=_create_function)

    update_parser = subparsers.add_parser("update", help="Update a tenant")
    update_parser.add_argument("-i", "--id", type=int, required=True)
    update_parser.add_argument("--display-name", dest="display_name", default=None)
    enable_group = update_parser.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", action="store_true", default=False)
    enable_group.add_argument("--disable", action="store_true", default=False)
    update_parser.set_defaults(func=_update_function)

    delete_parser = subparsers.add_parser("delete", help="Delete a tenant")
    delete_parser.add_argument("-i", "--id", type=int, required=True)
    delete_parser.set_defaults(func=_delete_function)
