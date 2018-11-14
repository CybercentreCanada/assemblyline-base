"""Sequence manipulation methods used in parsing raw datastore output."""
import typing


def chunk(l: typing.Sequence, n: int) -> typing.Generator:
    """ Yield n-sized chunks from list.

    >>> list(chunk([1,2,3,4,5,6,7], 2))
    [[1,2], [3,4], [5,6], [7,]]
    """
    for i in range(0, len(l), n):
        yield l[i:i+n]


def chunked_list(l: typing.Sequence, n: int) -> typing.List:
    """ Create a list of n-sized chunks from list.

    >>> chunked_list([1,2,3,4,5,6,7], 2)
    [[1,2], [3,4], [5,6], [7,]]
    """
    return list(chunk(l, n))
