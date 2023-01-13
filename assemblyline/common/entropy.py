import io

from math import ceil, log
from typing import Tuple, List, BinaryIO, AnyStr

frequency = None


def calculate_entropy(contents: bytes) -> float:
    """ this function calculates the entropy of the file
        It is given by the formula:
            E = -SUM[v in 0..255](p(v) * ln(p(v)))
    """
    calculator = BufferedCalculator()
    calculator.update(contents)
    return calculator.entropy()


def calculate_partition_entropy(fin: BinaryIO, num_partitions: int = 50) -> Tuple[float, List[float]]:
    """Calculate the entropy of a file and its partitions."""

    # Split input into num_parititions and calculate
    # parition entropy.
    fin.seek(0, io.SEEK_END)
    size = fin.tell()
    fin.seek(0)
    partition_size = int(ceil(size / float(num_partitions)))

    # Also calculate full file entropy using buffered calculator.
    p_entropies = []
    full_entropy_calculator = BufferedCalculator()
    for _ in range(num_partitions):
        partition = fin.read(partition_size)
        p_entropies.append(calculate_entropy(partition))
        full_entropy_calculator.update(partition)
    return full_entropy_calculator.entropy(), p_entropies


class BufferedCalculator(object):
    def __init__(self):
        global frequency
        import pyximport
        pyximport.install()
        # noinspection PyUnresolvedReferences
        from assemblyline.common import frequency

        self.c = {}
        self.length = 0

    def entropy(self) -> float:
        if self.length == 0:
            return 0.0

        length = float(self.length)

        entropy = 0.0
        for v in self.c.values():
            prob = float(v) / length
            entropy += prob * log(prob, 2)

        entropy *= -1

        # Make sure we don't return -0.0.
        if not entropy:
            entropy = 0.0

        return entropy

    def update(self, data: AnyStr, length: int = 0):
        if not length:
            length = len(data)

        self.length += length
        self.c = frequency.counts(data, length, self.c)
