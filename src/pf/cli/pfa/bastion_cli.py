import json

import tabulate

from ... import client


def _bastions(auth, id: int | None = None):
    params = {}
    if id is not None:
        params["id"] = id
    response = auth.get(auth.directory.bastion, params=params)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to find bastion {','.join(f'{k}={v}' for k, v in params.items())}")
    bastions = response.json()["bastions"]
    return bastions


def _bastion(args, auth):
    bastions = _bastions(auth, id=args.id)
    if len(bastions) == 0:
        raise client.exceptions.UI("No bastion found")
    assert len(bastions) == 1
    return bastions[0]


def _parse_tag(s):
    equal = s.find("=")
    if equal == -1:
        raise client.exceptions.UI(f"Tag is invalid. Expected format: name=value. Got: {s}")
    name = s[:equal]
    value = s[equal + 1 :]
    return {"name": name, "value": value}


def _bastion_list_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    bastions = _bastions(auth, id=args.id)
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(b["id"]) for b in bastions)
        case "json":
            output = json.dumps(bastions, indent=2)
        case "text":
            rows = []
            for bastion in bastions:
                rows.append([bastion["id"], bastion["register_url"], len(bastion.get("tag_list", []))])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(rows, headers=["id", "register_url", "ntags"], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _bastion_read_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    bastion = _bastion(args, auth)
    match args.format:
        case "json":
            output = json.dumps(bastion, indent=2)
        case "text":
            rows = []
            rows.append(["id", bastion["id"]])
            rows.append(["register_url", bastion["register_url"]])
            if bastion.get("connect_url"):
                rows.append(["connect_url", bastion["connect_url"]])
            if bastion.get("ssh_proxy_jump"):
                rows.append(["ssh_proxy_jump", bastion["ssh_proxy_jump"]])
            for tag in bastion.get("tag_list", []):
                rows.append(["tag", f"{tag['name']}={tag['value']}"])
            output = tabulate.tabulate(rows, tablefmt="plain")
        case _:
            assert False
    print(output)


def _bastion_delete_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.delete(f"{api.directory.bastion}/{args.id}")
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to delete bastion. {response.json()['title']}")


def _bastion_create_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    tag_id_list = [int(t) for t in args.tag if t.isdigit()]
    tag_name_value_list = [_parse_tag(t) for t in args.tag if not t.isdigit()]
    response = auth.post(
        api.directory.bastion,
        json={
            "register_url": args.register_url,
            "connect_url": args.connect_url,
            "ssh_proxy_jump": args.ssh_proxy_jump,
            "tag_id_list": tag_id_list,
            "tag_name_value_list": tag_name_value_list,
        },
    )
    if response.status_code != 201:
        raise client.exceptions.UI(f"Unable to create bastion. {response.json()['title']}")


def _bastion_update_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    query = {}
    if args.register_url is not None:
        query["register_url"] = args.register_url
    if args.connect_url is not None:
        query["connect_url"] = args.connect_url
    if args.ssh_proxy_jump is not None:
        query["ssh_proxy_jump"] = args.ssh_proxy_jump
    if not query:
        raise client.exceptions.UI("No fields to update")
    response = auth.patch(f"{api.directory.bastion}/{args.id}", json=query)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to update bastion. {response.json()['title']}.")


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser("list", help="List bastions")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-i", "--id", type=int, help="Id of bastion")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=_bastion_list_function)

    read_parser = subparsers.add_parser("read", help="Show details on a specific bastion")
    read_parser.add_argument("-i", "--id", type=int, help="Id of bastion", required=True)
    read_parser.add_argument("-f", "--format", choices=["json", "text"], default="text", help="Output format")
    read_parser.set_defaults(func=_bastion_read_function)

    create_parser = subparsers.add_parser("create", help="Create a new bastion")
    create_parser.add_argument("--register-url", type=str, required=True, help="Register URL of the bastion")
    create_parser.add_argument("--connect-url", type=str, help="Connect URL of the bastion")
    create_parser.add_argument("--ssh-proxy-jump", type=str, help="SSH ProxyJump string")
    create_parser.add_argument("-t", "--tag", help="Tag to apply on the bastion", nargs="*", default=[])
    create_parser.set_defaults(func=_bastion_create_function)

    delete_parser = subparsers.add_parser("delete", help="Delete a bastion")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of bastion", required=True)
    delete_parser.set_defaults(func=_bastion_delete_function)

    update_parser = subparsers.add_parser("update", help="Update a bastion")
    update_parser.add_argument("-i", "--id", type=int, help="Id of bastion", required=True)
    update_parser.add_argument("--register-url", type=str, help="Register URL of the bastion")
    update_parser.add_argument("--connect-url", type=str, help="Connect URL of the bastion")
    update_parser.add_argument("--ssh-proxy-jump", type=str, help="SSH ProxyJump string")
    update_parser.set_defaults(func=_bastion_update_function)
