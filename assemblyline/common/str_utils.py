import chardet
import re
from copy import copy
from typing import Union


def remove_bidir_unicode_controls(in_str):
    # noinspection PyBroadException
    try:
        no_controls_str = ''.join(
            c for c in in_str if c not in [
                u'\u202E', u'\u202B', u'\u202D',
                u'\u202A', u'\u200E', u'\u200F',
            ]
        )
    except Exception:
        no_controls_str = in_str

    return no_controls_str


def wrap_bidir_unicode_string(uni_str):
    """
    Wraps str in a LRE (Left-to-Right Embed) unicode control
    Guarantees that str can be concatenated to other strings without
    affecting their left-to-right direction
    """

    if len(uni_str) == 0 or isinstance(uni_str, bytes):  # Not str, return it unchanged
        return uni_str

    re_obj = re.search(r'[\u202E\u202B\u202D\u202A\u200E\u200F]', uni_str)
    if re_obj is None or len(re_obj.group()) == 0:  # No unicode bidir controls found, return string unchanged
        return uni_str

    # Parse str for unclosed bidir blocks
    count = 0
    for letter in uni_str:
        if letter in [u'\u202A', u'\u202B', u'\u202D', u'\u202E']:  # bidir block open?
            count += 1
        elif letter == u'\u202c':
            if count > 0:
                count -= 1

    # close all bidir blocks
    if count > 0:
        uni_str += (u'\u202c' * count)

        # Final wrapper (LTR block) to neutralize any Marks (u+200E and u+200F)
    uni_str = u'\u202A' + uni_str + u'\u202C'

    return uni_str


# According to wikipedia, RFC 3629 restricted UTF-8 to end at U+10FFFF.
# This removed the 6, 5 and (irritatingly) half of the 4 byte sequences.
#
# The start byte for 2-byte sequences should be a value between 0xc0 and
# 0xdf but the values 0xc0 and 0xc1 are invalid as they could only be
# the result of an overlong encoding of basic ASCII characters. There
# are similar restrictions on the valid values for 3 and 4-byte sequences.
_valid_utf8 = re.compile(rb"""((?:
    [\x09\x0a\x20-\x7e]|             # 1-byte (ASCII excluding control chars).
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


def safe_str(s, force_str=False):
    return escape_str(s, reversible=False, force_str=force_str)


def is_safe_str(s) -> bool:
    return escape_str(copy(s), reversible=False) == s


# noinspection PyBroadException
def translate_str(s, min_confidence=0.7) -> dict:
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
            t = s.decode(r['encoding'])
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
    string = safe_str(data)
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
