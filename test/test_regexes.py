import pytest
import re

from assemblyline.odm.base import FULL_URI, TLSH_REGEX


@pytest.mark.parametrize("value, ismatch", [
    ("blah", False),
    ("http://blah", False),
    ("http://blah.com", True),
    ("http://blah.com:abc", False),
    ("http://blah.com:123", True),
    ("http://blah.com:123?blah", True),
    ("http://blah.com:123/blah", True),
    ("http://blah.com:123/blah?blah", True),
    ("1.1.1.1", False),
    ("http://1.1.1.1", True),
    ("http://1.1.1.1:123", True),
    ("http://1.1.1.1:123/blah", True),
    ("http://1.1.1.1:123/blah?blah", True),
    ("net.tcp://1.1.1.1:123", True),
    ("net.tcp://1.1.1.1:1", True),
])
def test_full_uri_regex(value, ismatch):
    validation_regex = re.compile(FULL_URI)
    if ismatch:
        assert validation_regex.match(value) is not None
    else:
        assert validation_regex.match(value) is None


@pytest.mark.parametrize("value, ismatch", [
    ("T1A0F4F19BB9A15CDED5F2937AC6B293A35221FF23A357462F1498270D69202C8EA4D36F", True),
    ("abcdef01234567899876543210fedcba", False),
    ("A034F19BB7A15CDED5F2037AC6B293A35221FF23A357462F1498270D69202C8EA4D36F", True),
    ("034F1/9BB7A15CDED5F2037AC6B293A35221FF23A357462F1498270D69202C8EA4D36F", False),
    ("T1A034F19BB7A15CDEZ5F2037AC6B293A35221FF23A357462F1498270D69202C8EA4D36F", False),
    ("T1A034F19BB7A15CDED5F2037AC6B293A35221FF23A357462F1498270D69202C8EA4D36F2", False),
    ("T1a0f4f19bb9a15cded5f2937ac6b293a35221ff23a357462f1498270d69202c8ea4d36f", True),
    ("T1a0f4f19bb9a15cdED5F2937AC6B293A35221FF23A357462f1498270d69202c8ea4d36f", True),
    ("", False),
])
def test_tlsh_regex(value, ismatch):
    validation_regex = re.compile(TLSH_REGEX)
    if ismatch:
        assert validation_regex.match(value) is not None
    else:
        assert validation_regex.match(value) is None
