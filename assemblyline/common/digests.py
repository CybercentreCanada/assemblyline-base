import hashlib
import ssdeep
import tlsh
from typing import Dict

from assemblyline.common import entropy

DEFAULT_BLOCKSIZE = 65536


# noinspection PyBroadException
def get_digests_for_file(path: str, blocksize: int = DEFAULT_BLOCKSIZE, calculate_entropy: bool = True,
                         on_first_block=lambda _b, _l, _p: {}, skip_fuzzy_hashes: bool = False) -> Dict:
    """ Generate digests for file reading only 'blocksize bytes at a time."""
    bc = None
    if calculate_entropy:
        try:
            bc = entropy.BufferedCalculator()
        except Exception:
            pass

    result = {}

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    if not skip_fuzzy_hashes:
        th = tlsh.Tlsh()
    size = 0

    with open(path, 'rb') as f:
        data = f.read(blocksize)
        length = len(data)

        if not size:
            result.update(on_first_block(data, length, path))

        while length > 0:
            if bc is not None:
                bc.update(data, length)
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
            if not skip_fuzzy_hashes:
                th.update(data)
            size += length

            data = f.read(blocksize)
            length = len(data)

    if bc is not None:
        result['entropy'] = bc.entropy()
    else:
        result['entropy'] = 0
    result['md5'] = md5.hexdigest()
    result['sha1'] = sha1.hexdigest()
    result['sha256'] = sha256.hexdigest()
    result['size'] = size

    if not skip_fuzzy_hashes:
        result["ssdeep"] = ssdeep.hash_from_file(path)
        # Try to finalise the TLSH Hash and add it to the results
        try:
            th.final()
            result['tlsh'] = th.hexdigest()
        except Exception:
            pass

    return result


def get_md5_for_file(path: str, blocksize: int = DEFAULT_BLOCKSIZE) -> str:
    md5 = hashlib.md5()
    with open(path, 'rb') as f:
        data = f.read(blocksize)
        length = len(data)

        while length > 0:
            md5.update(data)
            data = f.read(blocksize)
            length = len(data)

        return md5.hexdigest()


def get_sha256_for_file(path: str, blocksize: int = DEFAULT_BLOCKSIZE) -> str:
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        data = f.read(blocksize)
        length = len(data)

        while length > 0:
            sha256.update(data)
            data = f.read(blocksize)
            length = len(data)

        return sha256.hexdigest()
