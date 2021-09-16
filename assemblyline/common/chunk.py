"""Sequence manipulation methods used in parsing raw datastore output."""
from __future__ import annotations
from typing import Sequence, Generator, TypeVar, overload

_T = TypeVar('_T')


@overload
def chunk(items: bytes, n: int) -> Generator[bytes, None, None]:
    ...


@overload
def chunk(items: str, n: int) -> Generator[str, None, None]:
    ...


@overload
def chunk(items: Sequence[_T], n: int) -> Generator[Sequence[_T], None, None]:
    ...


def chunk(items, n: int):
    """ Yield n-sized chunks from list.

    >>> list(chunk([1,2,3,4,5,6,7], 2))
    [[1,2], [3,4], [5,6], [7,]]
    """
    for i in range(0, len(items), n):
        yield items[i:i+n]


def chunked_list(items: Sequence[_T], n: int) -> list[Sequence[_T]]:
    """ Create a list of n-sized chunks from list.

    >>> chunked_list([1,2,3,4,5,6,7], 2)
    [[1,2], [3,4], [5,6], [7,]]
    """
    return list(chunk(items, n))
