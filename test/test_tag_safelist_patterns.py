import os
import re

import pytest
import yaml

SAFELIST_PATH = os.path.join(os.path.dirname(__file__), "..", "assemblyline", "common", "tag_safelist.yml")

with open(SAFELIST_PATH) as fh:
    SAFELIST_REGEX = yaml.safe_load(fh)["regex"]

# Unanchored search, start-anchored match and fully anchored match must all agree.
MATCH_MODES = [re.search, re.match, re.fullmatch]


@pytest.mark.parametrize("tag, value, safelisted", [
    ("network.static.uri", "http://schemas.openxmlformats.org/officeDocument/2006/relationships", True),
    ("network.static.uri", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", True),
    ("network.static.uri", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject", True),
    ("network.static.uri", "http://schemas.openxmlformats.org/officeDocument/2006/math", True),
    ("network.static.uri", "http://schemas.openxmlformats.org/package/2006/relationships", True),
    ("network.static.uri", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
     True),
    ("network.static.uri", "https://schemas.openxmlformats.org.evil.ru/package/2006/relationships/x", False),
    ("network.dynamic.uri", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", True),
    ("network.dynamic.uri", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
     True),
    ("network.dynamic.uri", "https://www.google.com", True),
    ("network.dynamic.uri", "https://www.google.ca/", True),
    ("network.dynamic.uri", "https://www.google.com.evil.ru/x", False),
    ("network.dynamic.uri", "https://files.acrobat.com", True),
    ("network.dynamic.uri", "https://files.acrobat.com:443", True),
    ("network.dynamic.uri", "files.acrobat.com/", True),
    ("network.dynamic.uri", "https://files.acrobat.com:443.evil.ru/x", False),
    ("network.dynamic.uri", "https://files.acrobat.com.evil.ru/", False),
    ("network.dynamic.domain", "foo.blob.core.windows.net", True),
    ("network.dynamic.domain", "foo.table.core.windows.net", True),
    ("network.dynamic.domain", "foo.opinsights.azure.com", True),
    ("network.dynamic.domain", "foo.blob.core.windows.net.evil.com", False),
    ("network.dynamic.domain", "foo.table.core.windows.net.evil.com", False),
    ("network.dynamic.domain", "foo.opinsights.azure.com.evil.com", False),
])
@pytest.mark.parametrize("mode", MATCH_MODES, ids=lambda m: m.__name__)
def test_tag_safelist_pattern_boundaries(mode, tag, value, safelisted):
    assert any(mode(p, value) for p in SAFELIST_REGEX[tag]) is safelisted
