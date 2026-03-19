import itertools


def group_by(seq, key):
    sorted_list = sorted(seq, key=key)
    return [(key, list(values)) for key, values in itertools.groupby(sorted_list, key=key)]
