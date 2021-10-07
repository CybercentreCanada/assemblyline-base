from __future__ import annotations
import os
import sys
from typing import Optional


def modulepath(modulename: str) -> str:
    m = sys.modules[modulename]
    f = getattr(m, '__file__', None)
    if not f:
        return os.path.abspath(os.getcwd())
    return os.path.dirname(os.path.abspath(f))


def splitpath(path: str, sep: Optional[str] = None) -> list:
    """ Split the path into a list of items """
    return list(filter(len, path.split(sep or os.path.sep)))


ASCII_NUMBERS = list(range(48, 58))
ASCII_UPPER_CASE_LETTERS = list(range(65, 91))
ASCII_LOWER_CASE_LETTERS = list(range(97, 123))
ASCII_OTHER = [45, 46, 92]  # "-", ".", and "\"

# Create a set that contains all of the valid characters that
# are allowed to appear in a Unified Naming Convention (UNC) path.
VALID_UNC_CHARS = [chr(x) for x in ASCII_LOWER_CASE_LETTERS +
                   ASCII_UPPER_CASE_LETTERS + ASCII_NUMBERS + ASCII_OTHER]


def is_unc_legal(path: str) -> bool:
    """Determine whether or not a given string representing a Windows file path is legal
    or not as per the Unified Naming Convention (UNC) specifications."""
    if len(path) <= 0:
        return False

    for char in path:
        if char not in VALID_UNC_CHARS:
            return False
    return True
