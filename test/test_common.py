
import os

from assemblyline.common.chunk import chunked_list

from assemblyline.common import forge


def test_chunk():
    assert [[1, 2], [3, 4], [5, 6], [7, 8]] == chunked_list([1, 2, 3, 4, 5, 6, 7, 8], 2)


def test_classification():
    pass


def test_compat_tag_map():
    pass


def test_dict_flatten():
    pass


def test_dict_unflatten():
    pass


def test_dict_recursive_update():
    pass


def test_dict_recursive_delta():
    pass


def test_entropy():
    pass


def test_hexdump():
    pass


def test_iprange():
    pass


def test_isotime():
    pass


def test_security():
    pass


def test_safe_str():
    pass


def test_uid():
    pass


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


