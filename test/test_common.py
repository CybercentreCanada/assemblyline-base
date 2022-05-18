
import hashlib
import io
import os
import zipfile

import pytest
import random
import re
import subprocess
import tempfile

from baseconv import BASE62_ALPHABET
from cart import pack_stream, get_metadata_only
from copy import deepcopy
from io import BytesIO

from assemblyline.common import forge
from assemblyline.common.attack_map import attack_map, software_map, group_map, revoke_map
from assemblyline.common.chunk import chunked_list, chunk
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.dict_utils import flatten, unflatten, recursive_update, get_recursive_delta
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline.common.heuristics import InvalidHeuristicException, HeuristicHandler
from assemblyline.common.hexdump import hexdump
from assemblyline.common.isotime import now_as_iso, iso_to_epoch, epoch_to_local, local_to_epoch, epoch_to_iso, now, \
    now_as_local
from assemblyline.common.iprange import is_ip_reserved, is_ip_private
from assemblyline.common.memory_zip import InMemoryZip
from assemblyline.common.security import get_random_password, get_password_hash, verify_password
from assemblyline.common.str_utils import safe_str, translate_str
from assemblyline.common.uid import get_random_id, get_id_from_data, TINY, SHORT, MEDIUM, LONG
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.randomizer import random_model_obj, get_random_word


def test_attack_map():
    # Validate the structure of the generated ATT&CK techniques map created by
    # assemblyline-base/external/generate_attack_map.py
    assert type(attack_map) == dict
    # This is the minimum set of keys that each technique entry in the attack map should have
    attack_technique_keys = {"attack_id", "categories", "description", "name", "platforms"}
    for attack_technique_id, attack_technique_details in attack_map.items():
        assert attack_technique_details.keys() == attack_technique_keys
        assert attack_technique_id == attack_technique_details["attack_id"]


def test_software_map():
    # Validate the structure of the generated ATT&CK software map created by
    # assemblyline-base/external/generate_attack_map.py
    assert type(software_map) == dict
    # This is the minimum set of keys that each technique entry in the attack map should have
    attack_software_keys = {"attack_ids", "description", "name", "platforms", "software_id", "type"}
    for attack_software_id, attack_software_details in software_map.items():
        assert attack_software_details.keys() == attack_software_keys
        assert attack_software_id == attack_software_details["software_id"]


def test_group_map():
    # Validate the structure of the generated ATT&CK group map (intrusion_set) created by
    # assemblyline-base/external/generate_attack_map.py
    assert type(group_map) == dict
    # This is the minimum set of keys that each technique entry in the attack map should have
    attack_group_keys = {"description", "group_id", "name"}
    for attack_group_id, attack_group_details in group_map.items():
        assert attack_group_details.keys() == attack_group_keys
        assert attack_group_id == attack_group_details["group_id"]


def test_revoke_map():
    # Validate the structure of the generated ATT&CK revoke_map created by
    # assemblyline-base/external/generate_attack_map.py
    assert type(revoke_map) == dict
    # This is the minimum set of keys that each technique entry in the attack map should have
    for revoked_id, mapped_id in revoke_map.items():
        assert revoked_id not in attack_map
        assert revoked_id not in software_map
        assert revoked_id not in group_map
        assert mapped_id in attack_map or mapped_id in software_map or mapped_id in group_map


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

    dyn1 = "U//TEST"
    dyn2 = "U//GOD//TEST"
    dyn3 = "U//TEST2"
    assert not cl_engine.is_valid(dyn1)
    assert not cl_engine.is_valid(dyn2)
    assert cl_engine.normalize_classification(dyn1, long_format=False) == "U"
    assert cl_engine.normalize_classification(dyn2, long_format=False) == "U//ADM"
    cl_engine.dynamic_groups = True
    assert cl_engine.is_valid(dyn1)
    assert cl_engine.is_valid(dyn2)
    assert cl_engine.is_valid(dyn3)
    assert cl_engine.is_accessible(dyn2, dyn1)
    assert not cl_engine.is_accessible(dyn1, dyn2)
    assert not cl_engine.is_accessible(dyn3, dyn1)
    assert not cl_engine.is_accessible(dyn1, dyn3)
    assert cl_engine.intersect_user_classification(dyn1, dyn1) == "UNRESTRICTED//REL TO TEST"
    assert cl_engine.max_classification(dyn1, dyn2) == "UNRESTRICTED//ADMIN//REL TO TEST"
    assert cl_engine.normalize_classification(dyn1, long_format=True) == "UNRESTRICTED//REL TO TEST"
    assert cl_engine.normalize_classification(dyn1, long_format=False) == "U//REL TO TEST"


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


def test_heuristics_valid():
    heuristic_list = [random_model_obj(Heuristic) for _ in range(4)]
    heuristics = {x.heur_id: x for x in heuristic_list}

    software_ids = list(set([random.choice(list(software_map.keys())) for _ in range(random.randint(1, 3))]))
    attack_ids = list(set([random.choice(list(attack_map.keys())) for _ in range(random.randint(1, 3))]))
    group_ids = list(set([random.choice(list(group_map.keys())) for _ in range(random.randint(1, 3))]))

    attack_ids_to_fetch_details_for = attack_ids[:]
    for software_id in software_ids:
        software_attack_ids = software_map[software_id]["attack_ids"]
        for software_attack_id in software_attack_ids:
            if software_attack_id in attack_map and software_attack_id not in attack_ids_to_fetch_details_for:
                attack_ids_to_fetch_details_for.append(software_attack_id)
            elif software_attack_id in revoke_map:
                revoked_id = revoke_map[software_attack_id]
                if revoked_id not in attack_ids_to_fetch_details_for:
                    attack_ids_to_fetch_details_for.append(revoked_id)
            else:
                print(f"Invalid related attack_id '{software_attack_id}' for software '{software_id}'. Ignoring it.")
    attack_id_details = {
        attack_id: {"pattern": attack_map[attack_id]["name"],
                    "categories": attack_map[attack_id]["categories"]} for attack_id in attack_ids_to_fetch_details_for}
    attack_ids.extend(software_ids)
    attack_ids.extend(group_ids)

    signatures = {}
    score_map = {}
    for x in range(random.randint(2, 4)):
        name = get_random_word()
        if x >= 2:
            score_map[name] = random.randint(10, 100)

        signatures[name] = random.randint(1, 3)

    service_heur = dict(
        heur_id=random.choice(list(heuristics.keys())),
        score=0,
        attack_ids=attack_ids,
        signatures=signatures,
        frequency=0,
        score_map=score_map
    )

    result_heur, _ = HeuristicHandler().service_heuristic_to_result_heuristic(deepcopy(service_heur), heuristics)
    assert result_heur is not None
    assert service_heur['heur_id'] == result_heur['heur_id']
    assert service_heur['score'] != result_heur['score']
    for attack in result_heur['attack']:
        attack_id = attack['attack_id']
        if attack_id in attack_map:
            assert attack_id in attack_ids_to_fetch_details_for
            assert attack['pattern'] == attack_id_details[attack_id]['pattern']
            assert attack['categories'] == attack_id_details[attack_id]['categories']
        elif attack_id in software_map:
            assert attack_id in software_ids
            assert attack['pattern'] == software_map[attack_id].get('name', attack_id)
            assert attack['categories'] == ['software']
        elif attack_id in group_map:
            assert attack_id in group_ids
            assert attack['pattern'] == group_map[attack_id].get('name', attack_id)
            assert attack['categories'] == ['group']
    for signature in result_heur['signature']:
        assert signature['name'] in signatures
        assert signature['frequency'] == signatures[signature['name']]


def test_heuristics_invalid():
    with pytest.raises(InvalidHeuristicException):
        HeuristicHandler().service_heuristic_to_result_heuristic({'heur_id': "my_id"}, {})


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


def test_identify():
    identify = forge.get_identify(use_cache=False)

    # Setup test data
    aaaa = f"{'A' * 10000}".encode()
    sha256 = hashlib.sha256(aaaa).hexdigest()

    # Prep temp file
    _, input_path = tempfile.mkstemp()
    output_path = f"{input_path}.cart"

    try:
        # Write temp file
        with open(input_path, 'wb') as oh:
            oh.write(aaaa)

        # Create a cart file
        with open(output_path, 'wb') as oh:
            with open(input_path, 'rb') as ih:
                pack_stream(ih, oh, {'name': 'test_identify.a'})

        # Validate the cart file created
        meta = get_metadata_only(output_path)
        assert meta.get("sha256", None) == sha256

        # Validate identify file detection
        info = identify.fileinfo(output_path)
        assert info.get("type", None) == "archive/cart"

        # Validate identify hashing
        output_sha256 = subprocess.check_output(['sha256sum', output_path])[:64].decode()
        assert info.get("sha256", None) == output_sha256
    finally:
        # Cleanup output file
        if os.path.exists(output_path):
            os.unlink(output_path)

        # Cleanup input file
        if os.path.exists(input_path):
            os.unlink(input_path)


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


def test_safe_str():
    assert safe_str("hello") == "hello"
    assert safe_str("hello\x00") == "hello\\x00"
    assert safe_str("\xf1\x90\x80\x80") == "\xf1\x90\x80\x80"
    assert safe_str("\xc2\x90") == "\xc2\x90"
    assert safe_str("\xc1\x90") == "\xc1\x90"


def test_tag_safelisting():
    forge.get_datastore().safelist.wipe()
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

    default_safelist = os.path.join(os.path.dirname(__file__), "..", "assemblyline", "common", "tag_safelist.yml")
    default_safelist = os.path.normpath(default_safelist)
    twl = forge.get_tag_safelister(yml_config=default_safelist)

    tag_map, safelisted_tag_map = twl.get_validated_tag_map(original_tag_map)
    assert original_tag_map != tag_map
    assert len(tag_map['network.static.ip']) == 3
    assert len(safelisted_tag_map['network.static.ip']) == 4
    assert len(tag_map['network.dynamic.ip']) == 1
    assert 'network.static.uri' not in tag_map
    assert len(safelisted_tag_map['network.static.uri']) == 2
    assert len(tag_map['network.dynamic.uri']) == 1
    assert len(safelisted_tag_map['network.dynamic.uri']) == 1
    assert len(tag_map['network.dynamic.domain']) == 2
    assert len(safelisted_tag_map['network.dynamic.domain']) == 1
    assert tag_map['network.static.domain'] == original_tag_map['network.static.domain']
    assert tag_map['file.behavior'] == original_tag_map['file.behavior']


def test_security():
    passwd = get_random_password()
    p_hash = get_password_hash(passwd)
    assert verify_password(passwd, p_hash)


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
    assert 23 > len(rid) >= 20
    assert 23 > len(id_test) >= 20
    assert 44 > len(id_test_l) >= 41
    assert 23 > len(id_test_m) >= 20
    assert 13 > len(id_test_s) >= 10
    assert 8 > len(id_test_t) >= 5
    assert id_test == id_test_m
    for c_id in [rid, id_test, id_test_l, id_test_m, id_test_s, id_test_t]:
        for x in c_id:
            assert x in BASE62_ALPHABET


def test_mem_zip():
    obj = InMemoryZip()
    obj.append('a.txt', 'abc abc')
    obj.append('b.txt', '11111111')

    buffer = io.BytesIO(obj.read())
    reader = zipfile.ZipFile(buffer)
    assert reader.read('a.txt') == b'abc abc'
    assert reader.read('b.txt') == b'11111111'
