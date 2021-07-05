import io

import array
from math import ceil, log
from typing import Tuple, List, BinaryIO, AnyStr, Optional

frequency = None


def calculate_byte_histogram(contents: AnyStr) -> Optional[array.array]:
    """ this function calculates a byte histrogram of the file.
    if the length of contents is 0 then None is returned
    """

    data_length = len(contents)
    count_bytes = array.array('L', [0] * 256)

    if data_length == 0:
        return count_bytes

    # keep a count of all the bytes
    for byte in contents:
        count_bytes[byte] += 1

    return count_bytes

def entropy_from_histogram(data_length: int, count_bytes: array.array):
    """ Given a byte histogram and  the length of the data it was derived from,
        this function will compute and return the Shannon entropy.
        Entropy is given by the formula:
            E = -SUM[v in 0..255](p(v) * ln(p(v)))
    """
    entropy = float(0)
    for value in count_bytes:
        if value:
            prob = (float(value) / data_length)
            entropy += (prob * log(prob, 2))
    entropy *= -1
    return entropy

def entropy_from_data(contents: AnyStr) -> Tuple[float, array.array]:
    """ this function calculates a byte histrogram and the entropy of the file
        and returns the histogram and the entropy.
        Entropy is given by the formula:
            E = -SUM[v in 0..255](p(v) * ln(p(v)))
    """

    count_bytes = calculate_byte_histogram(contents)
    data_length = len(contents)
    if data_length == 0:
        return (0.0, count_bytes)

    entropy = entropy_from_histogram(data_length, count_bytes)
    return (entropy, count_bytes)

def calculate_partition_entropy(fin: BinaryIO, num_partitions: int = 50) -> Tuple[Tuple[float, array.array], List[Tuple[float, array.array]]]::
    """Calculate the entropy of a file and its partitions."""

    # Split input into num_parititions and calculate
    # parition entropy.
    fin.seek(0, io.SEEK_END)
    size = fin.tell()
    fin.seek(0)
    partition_size = int(ceil(size / float(num_partitions)))

    # Also calculate full file entropy using buffered calculator.
    p_entropies = []
    fullentropy = BufferedCalculator()
    for _ in range(num_partitions):
        partition = fin.read(partition_size)
        p_entropies.append(entropy_from_data(partition))
        fullentropy.update(partition)
    return (entropy_from_histogram(fullentropy.length, fullentropy.count_bytes), fullentropy.count_bytes), p_entropies



class BufferedCalculator(object):
    def __init__(self):
        self.count_bytes = array.array('L', [0] * 256)
        self.length = 0

    def update(self, data: AnyStr, length: int = 0):
        if not length:
            length = len(data)
        self.length += length
        for byte in data:
            self.count_bytes[byte] += 1

