import itertools
import typing


class Sortable(typing.Protocol):
    def __lt__(self, other: typing.Any) -> bool: ...


def group_by[T, K: Sortable](
    seq: typing.Iterable[T],
    key: typing.Callable[[T], K]
) -> list[tuple[K, list[T]]]:

    sorted_list: list[T] = sorted(seq, key=key)
    groups = itertools.groupby(sorted_list, key=key)
    return [(k, list(v)) for k, v in groups]
