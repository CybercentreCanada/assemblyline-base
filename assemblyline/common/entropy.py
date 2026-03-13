import io

from math import log
from typing import Tuple, List, BinaryIO, AnyStr

from assemblyline_toolbox import BufferedCalculator

frequency = None

# The minimum partition size should be 256 bytes as the keyspace
# for a char is 256 bytes
MIN_PARTITION_SIZE = 256


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

    if size == 0:
        return 0, [0]

    # Calculate the partition size to get the desired amount of partitions but make sure those
    # partitions are the minimum partition size
    partition_size = max((size - 1)//num_partitions + 1, MIN_PARTITION_SIZE)

    # If our calculated partition size is the minimum partition size, our files is likely too small we will
    # calculate an alternate partition size that will make sure all blocks are equal size
    if partition_size == MIN_PARTITION_SIZE:
        partition_size = (size-1) // ((size-1)//partition_size + 1) + 1

    # Also calculate full file entropy using buffered calculator.
    p_entropies = []
    full_entropy_calculator = BufferedCalculator()
    for _ in range(num_partitions):
        partition = fin.read(partition_size)
        if not partition:
            break
        p_entropies.append(calculate_entropy(partition))
        full_entropy_calculator.update(partition)
    return full_entropy_calculator.entropy(), p_entropies

