import pytest
import re

from assemblyline.odm.base import FULL_URI



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
