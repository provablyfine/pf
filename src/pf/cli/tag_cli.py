import json

import tabulate

from . import client, config, exceptions


def _tags(args, auth):
    params = {}
    if args.id is not None:
        params["id"] = args.id
    if args.name is not None:
        params["name"] = args.name
    if args.value is not None:
        params["value"] = args.value
    response = auth.get(auth.directory.tag, params=params)
    if response.status_code != 200:
        raise exceptions.UI(f"Unable to find tags {','.join('='.join(kv) for kv in params.items())}")
    tags = response.json()["tags"]
    return tags


def _sort_by_id(t):
    return t["id"]


def _sort_by_name(t):
    return (t["name"], t["value"], t["id"])


def _sort_by_value(t):
    return (t["value"], t["name"], t["id"])


def tag_list_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    tags = _tags(args, auth)
    sort_functions = {
        "id": _sort_by_id,
        "name": _sort_by_name,
        "value": _sort_by_value,
    }
    tags = sorted(tags, key=sort_functions[args.sort])
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(t["id"]) for t in tags)
        case "json":
            output = json.dumps(tags, indent=2)
        case "text":
            rows = []
            for tag in tags:
                rows.append([tag["id"], tag["name"], tag["value"]])
            if rows:
                output = tabulate.tabulate(rows, headers=["id", "name", "value"])
            else:
                output = ""
        case _:
            assert False, args.format
    if output:
        print(output)


def _tag_create_function(args):
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.post(
        api.directory.tag,
        json={
            "name": args.name,
            "value": args.value,
        },
    )
    if response.status_code != 201:
        raise exceptions.UI(f"Unable to create tag. {response.json()['title']}")


def _tag_delete_function(args):
    if args.id is None and args.name is None and args.value is None:
        raise exceptions.UI("You must specify a filtering criterion")
    c = config.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.delete(f"{api.directory.tag}/{args.id}")
    if response.status_code != 204:
        raise exceptions.UI(f"Unable to delete tag. {response.json()['title']}")


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser("list", help="List tags we have access to")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-i", "--id", type=int, help="Id of tag.")
    group.add_argument("-n", "--name", type=str, help="Name of tag.")
    group.add_argument("-v", "--value", type=str, help="Value of tag.")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument(
        "-s", "--sort", choices=["id", "name", "value"], default="name", help="Sort criterion. Default: %(default)s"
    )
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=tag_list_function)

    create_parser = subparsers.add_parser("create", help="Create a new tag")
    create_parser.add_argument("-n", "--name", type=str, help="Name of tag.", required=True)
    create_parser.add_argument("-v", "--value", type=str, help="Value of tag.", required=True)
    create_parser.set_defaults(func=_tag_create_function)

    delete_parser = subparsers.add_parser("delete", help="Delete a tag")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of tag.")
    delete_parser.set_defaults(func=_tag_delete_function)
