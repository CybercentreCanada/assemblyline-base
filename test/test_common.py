
import os
import pytest
import random
import re

from copy import deepcopy
from io import BytesIO

from baseconv import BASE62_ALPHABET

from assemblyline.common import forge
from assemblyline.common.chunk import chunked_list, chunk
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.compat_tag_map import v3_lookup_map, tag_map, UNUSED
from assemblyline.common.dict_utils import flatten, unflatten, recursive_update, get_recursive_delta
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline.common.hexdump import hexdump
from assemblyline.common.isotime import now_as_iso, iso_to_epoch, epoch_to_local, local_to_epoch, epoch_to_iso, now, \
    now_as_local
from assemblyline.common.iprange import is_ip_reserved, is_ip_private
from assemblyline.common.security import get_random_password, get_password_hash, verify_password
from assemblyline.common.str_utils import safe_str, translate_str
from assemblyline.common.uid import get_random_id, get_id_from_data, TINY, SHORT, MEDIUM, LONG


def test_chunk():
    assert [[1, 2], [3, 4], [5, 6], [7, 8]] == chunked_list([1, 2, 3, 4, 5, 6, 7, 8], 2)


def test_classification():
    yml_config = os.path.join(os.path.dirname(__file__), "classification.yml")
    cl_engine = forge.get_classification(yml_config=yml_config)

    u = "U//REL TO DEPTS"
    r = "R//GOD//REL TO G1"

    assert cl_engine.normalize_classification(r, long_format=True) == "RESTRICTED//ADMIN//ANY/GROUP 1"
    assert cl_engine.is_accessible(r, u)
    assert cl_engine.is_accessible(u, u)
    assert not cl_engine.is_accessible(u, r)
    assert cl_engine.min_classification(u, r) == "UNRESTRICTED//REL TO DEPARTMENT 1, DEPARTMENT 2"
    assert cl_engine.max_classification(u, r) == "RESTRICTED//ADMIN//ANY/GROUP 1"
    assert cl_engine.intersect_user_classification(u, r) == "UNRESTRICTED//ANY"
    assert cl_engine.normalize_classification("UNRESTRICTED//REL TO DEPARTMENT 2", long_format=False) == "U//REL TO D2"
    with pytest.raises(InvalidClassification):
        cl_engine.normalize_classification("D//BOB//REL TO SOUP")

    c1 = "U//REL TO D1"
    c2 = "U//REL TO D2"
    assert cl_engine.min_classification(c1, c2) == "UNRESTRICTED//REL TO DEPARTMENT 1, DEPARTMENT 2"
    assert cl_engine.intersect_user_classification(c1, c2) == "UNRESTRICTED"
    with pytest.raises(InvalidClassification):
        cl_engine.max_classification(c1, c2)


def test_compat_tag_map():
    flatten_map = flatten(tag_map)
    for _ in range(10):
        random_key = random.choice(list(v3_lookup_map.keys()))
        try:
            assert random_key in flatten_map[v3_lookup_map[random_key]]
        except KeyError:
            assert random_key in UNUSED


def test_dict_flatten():
    src = {
        "a": {
            "b": {
                "c": 1
            }
        },
        "b": {
            "d": {
                2
            }
        }
    }

    flat_src = flatten(src)
    assert src == unflatten(flat_src)
    assert list(flat_src.keys()) == ["a.b.c", "b.d"]


def test_dict_recursive():
    src = {
        "a": {
            "b": {
                "c": 1
            }
        },
        "b": {
            "d": 2
        }
    }
    add = {
        "a": {
            "d": 3,
            "b": {
                "c": 4
            }
        }
    }
    dest = recursive_update(deepcopy(src), add)
    assert dest["a"]["b"]["c"] == 4
    assert dest["a"]["d"] == 3
    assert dest["b"]["d"] == 2

    delta = get_recursive_delta(src, dest)
    assert add == delta


def test_entropy():
    str_1 = "1" * 10000
    str_2 = bytes([random.randint(1, 255) for _ in range(10000)])

    e1, parts1 = calculate_partition_entropy(BytesIO(str_1.encode()), num_partitions=1)
    e2, parts2 = calculate_partition_entropy(BytesIO(str_2), num_partitions=1)
    assert e1 == 0
    assert e1 == parts1[0]
    assert e2 > 7.5
    assert e2 == parts2[0]


def test_hexdump():
    data = bytes([random.randint(1, 255) for _ in range(10000)])

    dumped = hexdump(data)
    line = dumped.splitlines()[random.randint(1, 200)]
    _ = int(line[:8], 16)
    assert len(line) == 77
    assert line[8:11] == ":  "
    for c in chunk(line[11:59], 3):
        assert c[0] in "abcdef1234567890"
        assert c[1] in "abcdef1234567890"
        assert c[2] == " "
    assert line[59:59+2] == "  "


def test_iprange():
    privates = ["10.10.10.10", "10.80.10.30",
                "172.16.16.16", "172.22.22.22", "172.30.30.30",
                "192.168.0.1", "192.168.245.245"]
    reserved = ["0.1.1.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "192.0.0.1", "192.0.2.0", "192.88.99.1",
                "198.19.1.1", "198.51.100.33", "203.0.113.20", "241.0.0.1", "225.1.1.1", "255.255.255.255"]
    public = ["44.33.44.33", "192.1.1.1", "111.111.111.111", "203.203.203.203", "199.199.199.199", "223.223.223.223"]

    for ip in privates:
        assert is_ip_private(ip)

    for ip in reserved:
        assert is_ip_reserved(ip)

    for ip in public:
        assert not is_ip_reserved(ip) and not is_ip_private(ip)


def test_isotime_iso():
    iso_date = now_as_iso()
    iso_format = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z')

    assert isinstance(iso_date, str)
    assert iso_format.match(iso_date)
    assert epoch_to_iso(iso_to_epoch(iso_date)) == iso_date
    assert iso_date == epoch_to_iso(local_to_epoch(epoch_to_local(iso_to_epoch(iso_date))))


def test_isotime_local():
    local_date = now_as_local()
    local_format = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}.*')

    assert isinstance(local_date, str)
    assert local_format.match(local_date)
    assert epoch_to_local(local_to_epoch(local_date)) == local_date
    assert local_date == epoch_to_local(iso_to_epoch(epoch_to_iso(local_to_epoch(local_date))))


def test_isotime_epoch():
    epoch_date = now(200)

    assert epoch_date == local_to_epoch(epoch_to_local(epoch_date))
    assert epoch_date == iso_to_epoch(epoch_to_iso(epoch_date))
    assert isinstance(epoch_date, float)


def test_isotime_rounding_error():
    for t in ["2020-01-29 18:41:25.758416", "2020-01-29 18:41:25.127600"]:
        epoch = local_to_epoch(t)
        local = epoch_to_local(epoch)
        assert local == t


def test_security():
    passwd = get_random_password()
    p_hash = get_password_hash(passwd)
    assert verify_password(passwd, p_hash)


def test_safe_str():
    assert safe_str("hello") == "hello"
    assert safe_str("hello\x00") == "hello\\x00"
    assert safe_str("\xf1\x90\x80\x80") == "\xf1\x90\x80\x80"
    assert safe_str("\xc2\x90") == "\xc2\x90"
    assert safe_str("\xc1\x90") == "\xc1\x90"


def test_translate_str():
    assert translate_str(b"\xf1\x90\x80\x80\xc2\x90")['encoding'] == "utf-8"
    assert translate_str(b"fran\xc3\xa7ais \xc3\xa9l\xc3\xa8ve")['encoding'] == "utf-8"
    assert translate_str(b'\x83G\x83\x93\x83R\x81[\x83f\x83B\x83\x93\x83O\x82'
                         b'\xcd\x93\xef\x82\xb5\x82\xad\x82\xc8\x82\xa2')['language'] == "Japanese"


def test_uid():
    test_data = "test" * 1000
    rid = get_random_id()
    id_test = get_id_from_data(test_data)
    id_test_l = get_id_from_data(test_data, length=LONG)
    id_test_m = get_id_from_data(test_data, length=MEDIUM)
    id_test_s = get_id_from_data(test_data, length=SHORT)
    id_test_t = get_id_from_data(test_data, length=TINY)
    assert 23 > len(rid) >= 21
    assert 23 > len(id_test) >= 21
    assert 44 > len(id_test_l) >= 42
    assert 23 > len(id_test_m) >= 21
    assert 13 > len(id_test_s) >= 11
    assert 8 > len(id_test_t) >= 6
    assert id_test == id_test_m
    for c_id in [rid, id_test, id_test_l, id_test_m, id_test_s, id_test_t]:
        for x in c_id:
            assert x in BASE62_ALPHABET


def test_whitelist():
    original_tag_map = {
        "network.static.ip": ['127.0.0.1', "1.1.1.1", "2.2.2.2", "192.168.22.22",
                              "172.19.2.33", "10.10.10.10", "172.40.23.23"],
        "network.dynamic.ip": "11.22.55.66",
        "network.static.uri": ['http://localhost/', "https://192.168.0.1"],
        "network.dynamic.uri": ['http://localhost', "https://193.168.0.1"],
        "network.dynamic.domain": ['cyber.gc.ca', "localhost", "localhost.net"],
        "network.static.domain": ['cse-cst.gc.ca', "google.ca", "microsoft.com"],
        "file.behavior": ["Can't touch this !"]
    }

    default_whitelist = os.path.join(os.path.dirname(__file__), "..", "assemblyline", "common", "tag_whitelist.yml")
    default_whitelist = os.path.normpath(default_whitelist)
    twl = forge.get_tag_whitelister(yml_config=default_whitelist)

    safe_tag_map = twl.get_validated_tag_map(original_tag_map)
    assert original_tag_map != safe_tag_map
    assert len(safe_tag_map['network.static.ip']) == 3
    assert len(safe_tag_map['network.dynamic.ip']) == 1
    assert len(safe_tag_map['network.static.uri']) == 0
    assert len(safe_tag_map['network.dynamic.uri']) == 1
    assert len(safe_tag_map['network.dynamic.domain']) == 2
    assert safe_tag_map['network.static.domain'] == original_tag_map['network.static.domain']
    assert safe_tag_map['file.behavior'] == original_tag_map['file.behavior']
