import yaml


class IndentDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        # This forces the list dash to be indented
        return super().increase_indent(flow, False)


def dump(data):
    output = yaml.dump(
        data,
        Dumper=IndentDumper,
        default_flow_style=False,
        indent=2,
        sort_keys=False,
    ).rstrip('\n')
    return output
