import argparse
import json

import tabulate

from ... import client


def _identities(
    auth,
    id: int | None = None,
    name: str | None = None,
    tag_id: int | None = None,
    tag_name: str | None = None,
    boundary_id: int | None = None,
    boundary_name: str | None = None,
):
    params = {}
    if id is not None:
        params["id"] = id
    if name is not None:
        params["name"] = name
    if tag_id is not None:
        params["tag_id"] = tag_id
    if tag_name is not None:
        params["tag_name"] = tag_name
    if boundary_id is not None:
        params["boundary_id"] = boundary_id
    if boundary_name is not None:
        params["boundary_name"] = boundary_name
    response = auth.get(auth.directory.identity, params=params)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to find identity {','.join('='.join(kv) for kv in params.items())}")
    identities = response.json()["identities"]
    return identities


def _identity(args, auth):
    identities = _identities(auth, id=args.id)
    if len(identities) == 0:
        raise client.exceptions.UI("No identity found")
    assert len(identities) == 1
    return identities[0]


def _tag(tag: str):
    if tag.isdigit():
        return {"id": int(tag)}
    else:
        equal = tag.find("=")
        if equal == -1:
            raise client.exceptions.UI(f"Tag format is name=value, not {tag}")
        name = tag[:equal]
        value = tag[equal + 1 :]
        return {"name": name, "value": value}


def _boundary(s: str):
    if s.isdigit():
        return {"id": int(s)}
    else:
        return {"name": s}


def _identity_list_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    identities = _identities(
        auth,
        id=args.id,
        name=args.name,
        tag_id=args.tag_id,
        tag_name=args.tag_name,
        boundary_id=args.boundary_id,
        boundary_name=args.boundary_name,
    )
    if args.quiet:
        args.format = "quiet"
    match args.format:
        case "quiet":
            output = "\n".join(str(i["id"]) for i in identities)
        case "json":
            output = json.dumps(identities, indent=2)
        case "text":
            rows = []
            for identity in identities:
                rows.append([identity["id"], identity["name"], len(identity["tags"]), len(identity["boundaries"])])
            if len(rows) == 0:
                output = ""
            else:
                output = tabulate.tabulate(rows, headers=["id", "name", "ntags", "nboundaries"], maxcolwidths=80)
        case _:
            assert False
    if output:
        print(output)


def _identity_read_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    identity = _identity(args, auth)
    match args.format:
        case "json":
            output = json.dumps(identity, indent=2)
        case "text":
            rows = []
            rows.append(("id", identity["id"]))
            rows.append(("name", identity["name"]))
            for t in identity["tags"]:
                rows.append(("tag", f"{t['name']}={t['value']}"))
            for b in identity["boundaries"]:
                rows.append(("boundary", b["name"]))
            output = tabulate.tabulate(rows, tablefmt="plain")
        case _:
            assert False
    print(output)


def _identity_delete_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.delete(f"{api.directory.identity}/{args.id}")
    if response.status_code != 204:
        raise client.exceptions.UI(f"Unable to delete identity. {response.json()['title']}")


def _parse_tag(s):
    equal = s.find("=")
    if equal == -1:
        raise client.exceptions.UI(f"Tag is invalid. Expected format: name=value. Got: {s}")
    name = s[:equal]
    value = s[equal + 1 :]
    return {"name": name, "value": value}


def _identity_create_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    boundary_id_list = [int(b) for b in args.boundary if b.isdigit()]
    boundary_name_list = [b for b in args.boundary if not b.isdigit()]
    tag_id_list = [int(t) for t in args.tag if t.isdigit()]
    tag_name_value_list = [_parse_tag(t) for t in args.tag if not t.isdigit()]
    response = auth.post(
        api.directory.identity,
        json={
            "name": args.name,
            "boundary_id_list": boundary_id_list,
            "boundary_name_list": boundary_name_list,
            "tag_id_list": tag_id_list,
            "tag_name_value_list": tag_name_value_list,
        },
    )
    if response.status_code != 201:
        raise client.exceptions.UI(f"Unable to create identity. {response.json()['title']}")


def _identity_invite_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    response = auth.post(f"{api.directory.identity}/{args.id}/invite", json={"delivery": args.delivery})
    if response.status_code == 204:
        return
    elif response.status_code == 200:
        data = response.json()
        print(data["key"]["k"])
    else:
        raise client.exceptions.UI(f"Unable to invite identity. {response.json()['title']}")


def _identity_update_function(args):
    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)
    query = {}
    if args.name is not None:
        query["name"] = args.name
    response = auth.patch(f"{api.directory.identity}/{args.id}", json=query)
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to update identity. {response.json()['title']}.")


class TagAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        # Get the current list or initialize a new one
        items = getattr(namespace, self.dest, [])
        if items is None:
            items = []

        items.append((self.const, values))

        setattr(namespace, self.dest, items)


def _format_tag_op(op, values):
    tag_id_list = [int(t) for t in values if t.isdigit()]
    tag_name_value_list = [_parse_tag(t) for t in values if not t.isdigit()]
    output = []
    if len(tag_id_list) > 0:
        output.append({"type": op, "tag_id_list": tag_id_list})
    if len(tag_name_value_list) > 0:
        output.append({"type": op, "tag_name_value_list": tag_name_value_list})
    return output


def _identity_tag_function(args):

    c = client.Config.load(args.config)
    api = client.Client(c)
    auth = api.session_auth(c.session_key)

    ops = [op for op_type, values in args.ops for op in _format_tag_op(op_type, values)]

    response = auth.patch(
        f"{api.directory.identity}/{args.id}",
        json={
            "tags": ops,
        },
    )
    if response.status_code != 200:
        raise client.exceptions.UI(f"Unable to update identity. {response.json()['title']}.")


def add_subparser(parser):
    subparsers = parser.add_subparsers(required=True)

    list_parser = subparsers.add_parser("list", help="List identities we have access to")
    group = list_parser.add_argument_group(title="Filter criteria")
    group.add_argument("-i", "--id", type=int, help="Id of identity")
    group.add_argument("-n", "--name", type=str, help="Name of identity")
    group.add_argument("--tag-id", type=str, help="Id of tag applied to identity", nargs="*")
    group.add_argument("--tag-name", type=str, help="Name of tag applied to identity", nargs="*")
    group.add_argument("--boundary-id", type=str, help="Id of boundary applied to identity", nargs="*")
    group.add_argument("--boundary-name", type=str, help="Name of boundary applied to identity", nargs="*")
    group = list_parser.add_argument_group(title="Formatting criteria")
    group.add_argument(
        "-s", "--sort", choices=["id", "name", "value"], default="name", help="Sort criterion. Default: %(default)s"
    )
    group.add_argument("-q", "--quiet", help="Equivalent to -f quiet", action="store_true")
    group.add_argument("-f", "--format", choices=["json", "text", "quiet"], default="text", help="Output format")
    list_parser.set_defaults(func=_identity_list_function)

    read_parser = subparsers.add_parser("read", help="Show details on a specific identity")
    read_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    read_parser.add_argument("-f", "--format", choices=["json", "text"], default="text", help="Output format")
    read_parser.set_defaults(func=_identity_read_function)

    create_parser = subparsers.add_parser("create", help="Create a new identity")
    create_parser.add_argument("-n", "--name", type=str, help="Name of identity. Must be globally unique.")
    create_parser.add_argument(
        "-b", "--boundary", help="Boundary to enforce on newly-created identity", nargs="*", default=[]
    )
    create_parser.add_argument("-t", "--tag", help="Tag to apply on the newly-created identity", nargs="*", default=[])
    create_parser.set_defaults(func=_identity_create_function)

    invite_parser = subparsers.add_parser("invite", help="Invite an identity")
    invite_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    group = invite_parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--manual",
        action="store_const",
        const="manual",
        dest="delivery",
        help="Print the invitation. You are responsible for sharing this invitation securely with the user.",
    )
    group.add_argument(
        "--email", action="store_const", const="email", dest="delivery", help="Send the invitation by email"
    )
    invite_parser.set_defaults(func=_identity_invite_function)

    delete_parser = subparsers.add_parser("delete", help="Delete an unused identity")
    delete_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    delete_parser.set_defaults(func=_identity_delete_function)

    update_parser = subparsers.add_parser("update", help="Update an existing identity")
    update_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    update_parser.add_argument("-n", "--name", help="New name of identity")
    update_parser.set_defaults(func=_identity_update_function)

    tag_parser = subparsers.add_parser(
        "tag", help="Update the list of tags assigned to an identity. Commands are processed in-order"
    )
    tag_parser.add_argument("-i", "--id", type=int, help="Id of identity")
    tag_parser.add_argument(
        "-s", "--set", metavar="tag", dest="ops", const="set", help="Set list of tags", action=TagAction, nargs="*"
    )
    tag_parser.add_argument(
        "-a", "--add", metavar="tag", dest="ops", const="add", help="Add tag to identity", action=TagAction, nargs="*"
    )
    tag_parser.add_argument(
        "-d",
        "--del",
        metavar="tag",
        dest="ops",
        const="del",
        help="Delete tag from identity",
        action=TagAction,
        nargs="*",
    )
    tag_parser.set_defaults(func=_identity_tag_function)
