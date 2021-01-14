import pytest

from assemblyline.common import str_utils


def test_named_constants():
    named_const_test = str_utils.NamedConstants("test", [
        ("a", 1),
        ("B", 2),
        ("c", 3)
    ])
    # success tests
    assert named_const_test.name_for_value(1) == 'a'
    assert named_const_test.contains_value(1) is True
    assert named_const_test['a'] == 1
    assert named_const_test.c == 3
    # failure tests
    assert named_const_test.contains_value(4) is False
    with pytest.raises(KeyError):
        assert named_const_test.name_for_value(4) is None
        assert named_const_test['b'] == 2
        assert named_const_test.C == 3


def test_dotdump():
    result = str_utils.dotdump([1, 8, 22, 33, 66, 99, 126, 127, 1000])
    assert result == "...!Bc~.."


def test_translate_str():
    teststr = 'Стамболийски'
    encoded_test_str = teststr.encode('ISO-8859-5')
    result = str_utils.translate_str(encoded_test_str)
    assert result['language'] == 'Bulgarian'
    assert result['encoding'] == 'ISO-8859-5'
    result = str_utils.translate_str('abcdéfg')
    assert result['language'] == 'unknown'
    assert result['encoding'] == 'utf-8'


def test_remove_bidir_unicode_controls():
    test_str = 'a\u202Db\u202Ac\u200Ed\u200Fe\u202Efg\u202B'
    assert str_utils.remove_bidir_unicode_controls(test_str) == 'abcdefg'

    other_test_str = 'abcdéfg'
    assert str_utils.remove_bidir_unicode_controls(other_test_str) == 'abcdéfg'


def test_wrap_bidir_unicode_string():
    test_str = 'a\u202Db\u202Acde\u202Efg\u202B'
    a = str_utils.wrap_bidir_unicode_string(test_str)
    assert a == '\u202aa\u202db\u202Acde\u202efg\u202b\u202c\u202c\u202c\u202c\u202c'

    byte_str = b'\u202Dabcdefg'
    assert str_utils.wrap_bidir_unicode_string(byte_str) == b'\u202Dabcdefg'

    fail_search_str = 'abcdefg'
    assert str_utils.wrap_bidir_unicode_string(fail_search_str) == 'abcdefg'

    already_closed_str = 'abc\u202Adef\u202cg'
    assert str_utils.wrap_bidir_unicode_string(already_closed_str) == '\u202Aabc\u202Adef\u202cg\u202C'
