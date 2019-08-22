"""Sequence manipulation methods used in parsing raw datastore output."""
from typing import Sequence, Generator, List


def chunk(l: Sequence, n: int) -> Generator:
    """ Yield n-sized chunks from list.

    >>> list(chunk([1,2,3,4,5,6,7], 2))
    [[1,2], [3,4], [5,6], [7,]]
    """
    for i in range(0, len(l), n):
        yield l[i:i+n]


def chunked_list(l: Sequence, n: int) -> List:
    """ Create a list of n-sized chunks from list.

    >>> chunked_list([1,2,3,4,5,6,7], 2)
    [[1,2], [3,4], [5,6], [7,]]
    """
    return list(chunk(l, n))
