import itertools
import typing


class Sortable(typing.Protocol):
    def __lt__(self, other: typing.Any) -> bool: ...

type GroupedResult[K, T] = list[tuple[K, list[T]]]

def group_by[T, K: Sortable](
    seq: typing.Iterable[T],
    key: typing.Callable[[T], K]
) -> GroupedResult[K, T]:

    sorted_list: list[T] = sorted(seq, key=key)
    groups = itertools.groupby(sorted_list, key=key)
    return [(k, list(v)) for k, v in groups]
