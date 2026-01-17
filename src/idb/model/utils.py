import itertools

def group_by(l, key):
    sorted_list = sorted(l, key=key)
    return [(key, list(values)) for key, values in itertools.groupby(sorted_list, key=key)]
