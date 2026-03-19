import re
from copy import copy
from enum import Enum
from typing import Literal, Union, overload

import chardet

# Reference: https://unicode.org/reports/tr9/#Directional_Formatting_Characters
class DirectionalFormattingCharacter(Enum):
    LRE = u'\u202A' # Left-to-Right Embedding
    RLE = u'\u202B' # Right-to-Left Embedding
    PDF = u'\u202C' # Pop Directional Formatting
    LRO = u'\u202D' # Left-to-Right Override
    RLO = u'\u202E' # Right-to-Left Override
    LRI = u'\u2066' # Left-to-Right Isolate
    RLI = u'\u2067' # Right-to-Left Isolate
    FSI = u'\u2068' # First Strong Isolate
    PDI = u'\u2069' # Pop Directional Isolate
    LRM = u'\u200E' # Left-to-Right Mark
    RLM = u'\u200F' # Right-to-Left Mark
    ALM = u'\u061C' # Arabic Letter Mark

CONTROL_CHARS = []
EO_CONTROL_CHARS = []
I_CONTROL_CHARS = []

for c in DirectionalFormattingCharacter:
    CONTROL_CHARS.append(c.value)
    if c in [DirectionalFormattingCharacter.LRE, DirectionalFormattingCharacter.RLE,
             DirectionalFormattingCharacter.LRO, DirectionalFormattingCharacter.RLO]:
        EO_CONTROL_CHARS.append(c.value)
    elif c in [DirectionalFormattingCharacter.LRI, DirectionalFormattingCharacter.RLI,
               DirectionalFormattingCharacter.FSI]:
        I_CONTROL_CHARS.append(c.value)

def remove_bidir_unicode_controls(in_str: str):
    # noinspection PyBroadException
    try:
        no_controls_str = ''.join(c for c in in_str if c not in CONTROL_CHARS)
    except Exception:
        no_controls_str = in_str

    return no_controls_str


def wrap_bidir_unicode_string(uni_str: Union[str, bytes]) -> Union[str, bytes]:
    """
    Wraps str in a LRE (Left-to-Right Embed) unicode control
    Guarantees that str can be concatenated to other strings without
    affecting their left-to-right direction
    """

    if len(uni_str) == 0 or isinstance(uni_str, bytes):  # Not str, return it unchanged
        return uni_str

    re_obj = re.search(rf"[{''.join(CONTROL_CHARS)}]", uni_str)
    if re_obj is None or len(re_obj.group()) == 0:  # No unicode bidir controls found, return string unchanged
        return uni_str

    # Parse str for unclosed bidir blocks
    idf_count = 0   # Isolate Directional Formatting Count
    eodf_count = 0  # Embedding and Override Directional Formatting Count

    for letter in uni_str:
        # Look for block open with embedded or override characters
        if letter in EO_CONTROL_CHARS:
            eodf_count += 1
        # Look for block close with embedded or override characters
        elif letter == DirectionalFormattingCharacter.PDF.value:
            if eodf_count > 0:
                eodf_count -= 1
        # Look for block open with isolate characters
        elif letter in I_CONTROL_CHARS:
            idf_count += 1
        # Look for block close with isolate characters
        elif letter == DirectionalFormattingCharacter.PDI.value:
            if idf_count > 0:
                idf_count -= 1

    # close all bidir blocks
    if eodf_count > 0:
        uni_str += (DirectionalFormattingCharacter.PDF.value * eodf_count)
    if idf_count > 0:
        uni_str += (DirectionalFormattingCharacter.PDI.value * idf_count)

    # Final wrapper (LTR block) to neutralize any Marks (u+200E, u+200F and u+061C)
    uni_str = DirectionalFormattingCharacter.LRE.value + uni_str + DirectionalFormattingCharacter.PDF.value

    return uni_str


# According to wikipedia, RFC 3629 restricted UTF-8 to end at U+10FFFF.
# This removed the 6, 5 and (irritatingly) half of the 4 byte sequences.
#
# The start byte for 2-byte sequences should be a value between 0xc0 and
# 0xdf but the values 0xc0 and 0xc1 are invalid as they could only be
# the result of an overlong encoding of basic ASCII characters. There
# are similar restrictions on the valid values for 3 and 4-byte sequences.
_valid_utf8 = re.compile(rb"""((?:
    [\x09\x0a\x0d\x20-\x7e]|         # 1-byte (ASCII excluding control chars).
    [\xc2-\xdf][\x80-\xbf]|          # 2-bytes (excluding overlong sequences).
    [\xe0][\xa0-\xbf][\x80-\xbf]|    # 3-bytes (excluding overlong sequences).

    [\xe1-\xec][\x80-\xbf]{2}|       # 3-bytes.
    [\xed][\x80-\x9f][\x80-\xbf]|    # 3-bytes (up to invalid code points).
    [\xee-\xef][\x80-\xbf]{2}|       # 3-bytes (after invalid code points).

    [\xf0][\x90-\xbf][\x80-\xbf]{2}| # 4-bytes (excluding overlong sequences).
    [\xf1-\xf3][\x80-\xbf]{3}|       # 4-bytes.
    [\xf4][\x80-\x8f][\x80-\xbf]{2}  # 4-bytes (up to U+10FFFF).
    )+)""", re.VERBOSE)


def _escape(t, reversible=True):
    if t[0] % 2:
        return t[1].replace(b'\\', b'\\\\') if reversible else t[1]
    else:
        return b''.join((b'\\x%02x' % x) for x in t[1])


def dotdump(s):
    if isinstance(s, str):
        s = s.encode()
    return ''.join(['.' if x < 32 or x > 126 else chr(x) for x in s])


def escape_str(s, reversible=True, force_str=False) -> str:
    if isinstance(s, bytes):
        return escape_str_strict(s, reversible)
    elif not isinstance(s, str):
        if force_str:
            return str(s)
        return s

    try:
        return escape_str_strict(s.encode('utf-16', 'surrogatepass').decode('utf-16').encode('utf-8'), reversible)
    except Exception:
        return escape_str_strict(s.encode('utf-8', errors="backslashreplace"), reversible)


# Returns a string (str) with only valid UTF-8 byte sequences.
def escape_str_strict(s: bytes, reversible=True) -> str:
    escaped = b''.join([_escape(t, reversible)
                        for t in enumerate(_valid_utf8.split(s))])
    return escaped.decode('utf-8')


@overload
def safe_str(s: object, force_str: Literal[True]) -> str: ...


@overload
def safe_str(s: Union[str, bytes], force_str: Literal[False] = False) -> str: ...


def safe_str(s, force_str=False):
    return escape_str(s, reversible=False, force_str=force_str)


def is_safe_str(s) -> bool:
    return escape_str(copy(s), reversible=False) == s


# noinspection PyBroadException
def translate_str(s: Union[str, bytes], min_confidence=0.7) -> dict:
    if not isinstance(s, (str, bytes)):
        raise TypeError(f'Expected str or bytes got {type(s)}')

    if isinstance(s, str):
        s = s.encode("utf-8")

    try:
        r = chardet.detect(s)
    except Exception:
        r = {'confidence': 0.0, 'encoding': None, 'language': None}

    if r['confidence'] > 0 and r['confidence'] >= min_confidence:
        try:
            t: Union[bytes, str] = s.decode(r['encoding'])
        except Exception:
            t = s
    else:
        t = s

    r['converted'] = safe_str(t)
    r['encoding'] = r['encoding'] or 'unknown'
    r['language'] = r['language'] or 'unknown'

    return r


# This method not really necessary. More to stop people from rolling their own.
def unescape_str(s):
    return s.decode('string_escape')


def truncate(data: Union[bytes, str], length: int = 100) -> str:
    """
    This method is a helper used to avoid cluttering output
    :param data: The buffer that will be determined if it needs to be sliced
    :param length: The limit of characters to the buffer
    :return str: The potentially truncated buffer
    """
    # We need to force the value to be a string because the output is a string
    string = safe_str(data, force_str=True)
    if len(string) > length:
        return string[:length] + '...'
    return string


class NamedConstants(object):

    def __init__(self, name, string_value_list):
        self._name = name
        self._value_map = dict(string_value_list)
        self._reverse_map = dict([(s[1], s[0]) for s in string_value_list])

        # we also import the list as attributes so things like
        # tab completion and introspection still work.
        for s, v in self._value_map.items():
            setattr(self, s, v)

    def name_for_value(self, v):
        return self._reverse_map[v]

    def contains_value(self, v):
        return v in self._reverse_map

    def __getitem__(self, s):
        return self._value_map[s]

    def __getattr__(self, s):
        # We implement our own getattr mainly to provide the better exception.
        return self._value_map[s]


class StringTable(object):

    def __init__(self, name, string_value_list):
        self._name = name
        self._value_map = dict(string_value_list)
        self._reverse_map = dict([(s[1], s[0]) for s in string_value_list])

        # we also import the list as attributes so things like
        # tab completion and introspection still work.
        for s in self._value_map.keys():
            setattr(self, s, s)

    def name_for_value(self, v):
        return self._reverse_map[v]

    def contains_string(self, s):
        return s in self._reverse_map

    def contains_value(self, v):
        return v in self._value_map

    def __getitem__(self, s):
        if s in self._value_map:
            return s
        raise AttributeError("Invalid value for %s (%s)" % (self._name, s))

    def __getattr__(self, s):
        # We implement our own getattr mainly to provide the better exception.
        if s in self._value_map:
            return s
        raise AttributeError("Invalid value for %s (%s)" % (self._name, s))

    def keys(self) -> list:
        return list(self._value_map.keys())
