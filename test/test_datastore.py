import pytest
import random
import string
import time
import warnings

from datemath import dm
from retrying import retry

from assemblyline.common.testing import skip
from assemblyline.datastore import Collection

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    test_map = {
        'test1': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'test1_s': 'hello', 'tags_ss': ['a', 'b', 'c']},
        'test2': {'expiry_dt': dm('now-1d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 100, 'test2_s': 'hello', 'tags_ss': ['a', 'b', 'f']},
        'test3': {'expiry_dt': dm('now/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 200, 'test3_s': 'hello', 'tags_ss': ['a', 'b', 'e']},
        'test4': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'test4_s': 'hello', 'tags_ss': ['a', 'b', 'd']},
        'dict1': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'classification_s': 'U', 'test1_s': 'hello', 'tags_ss': []},
        'dict2': {'expiry_dt': dm('now/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 100, 'classification_s': 'U', 'test2_s': 'hello', 'tags_ss': []},
        'dict3': {'expiry_dt': dm('now-3d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 200, 'classification_s': 'C', 'test3_s': 'hello', 'tags_ss': []},
        'dict4': {'expiry_dt': dm('now-1d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'classification_s': 'TS', 'test4_s': 'hello', 'tags_ss': []},
        'string': "A string!",
        'list': ['a', 'list', 'of', 'string', 100],
        'int': 69,
        'to_update': {'counters': {'lvl_i': 100, "inc_i": 0, "dec_i": 100}, "list": ['hello', 'remove'], "map": {'a': 1}},
        'bulk_update': {'bulk_b': True, "map": {'a': 1}, 'counters': {
            'lvl_i': 100, "inc_i": 0, "dec_i": 100}, "list": ['hello', 'remove']},
        'bulk_update2': {'bulk_b': True, "map": {'a': 1}, 'counters': {
            'lvl_i': 100, "inc_i": 0, "dec_i": 100}, "list": ['hello', 'remove']},
        'delete1': {'delete_b': True, 'lvl_i': 100},
        'delete2': {'delete_b': True, 'lvl_i': 300},
        'delete3': {'delete_b': True, 'lvl_i': 400},
        'delete4': {'delete_b': True, 'lvl_i': 200}
    }


class SetupException(Exception):
    pass


@retry(stop_max_attempt_number=10, wait_random_min=100, wait_random_max=500)
def setup_store(docstore, request):
    try:
        ret_val = docstore.ping()
        if ret_val:
            collection_name = ''.join(random.choices(string.ascii_lowercase, k=10))
            docstore.register(collection_name)
            collection = docstore.__getattr__(collection_name)
            request.addfinalizer(collection.wipe)

            # cleanup
            for k in test_map.keys():
                collection.delete(k)

            for k, v in test_map.items():
                collection.save(k, v)

            # Commit saved data
            collection.commit()

            return collection
    except ConnectionError:
        pass
    raise SetupException("Could not setup Datastore: %s" % docstore.__class__.__name__)


@pytest.fixture(scope='module')
def solr_connection(request):
    from assemblyline.datastore.stores.solr_store import SolrStore

    try:
        collection = setup_store(SolrStore(['127.0.0.1']), request)
    except SetupException:
        collection = None

    if collection:
        return collection

    return skip("Connection to the SOLR server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def es_connection(request):
    from assemblyline.datastore.stores.es_store import ESStore

    try:
        collection = setup_store(ESStore(['127.0.0.1']), request)
    except SetupException:
        collection = None

    if collection:
        return collection

    return skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


def _test_get(c: Collection):
    # Test GET
    assert test_map.get('test1') == c.get('test1')
    assert test_map.get('test2') == c.get('test2')
    assert test_map.get('test3') == c.get('test3')
    assert test_map.get('test4') == c.get('test4')
    assert test_map.get('string') == c.get('string')
    assert test_map.get('list') == c.get('list')
    assert test_map.get('int') == c.get('int')


def _test_multiget(c: Collection):
    # TEST Multi-get
    raw = [test_map.get('test1'), test_map.get('int'), test_map.get('test2')]
    ds_raw = c.multiget(['test1', 'int', 'test2'], as_dictionary=False)
    for item in ds_raw:
        raw.remove(item)
    assert len(raw) == 0

    for k, v in c.multiget(['test1', 'int', 'test2'], as_dictionary=True).items():
        assert test_map[k] == v


def _test_keys(c: Collection):
    # Test KEYS
    test_keys = list(test_map.keys())
    for k in c.keys():
        test_keys.remove(k)
    assert len(test_keys) == 0


def _test_update(c: Collection):
    # Test Update
    expected = {'counters': {'lvl_i': 666, 'inc_i': 50, 'dec_i': 50}, 'list': ['hello', 'world!'], "map": {'b': 99}}
    operations = [
        (c.UPDATE_SET, "counters.lvl_i", 666),
        (c.UPDATE_INC, "counters.inc_i", 50),
        (c.UPDATE_DEC, "counters.dec_i", 50),
        (c.UPDATE_APPEND, "list", "world!"),
        (c.UPDATE_REMOVE, "list", "remove"),
        (c.UPDATE_DELETE, "map", "a"),
        (c.UPDATE_SET, "map.b", 99),
    ]
    assert c.update('to_update', operations)
    assert c.get('to_update') == expected


def _test_update_by_query(c: Collection):
    # Test update_by_query
    expected = {'bulk_b': True, 'counters': {'lvl_i': 666, 'inc_i': 50, 'dec_i': 50}, 'list': ['hello', 'world!'], "map": {'b': 99}}
    operations = [
        (c.UPDATE_SET, "counters.lvl_i", 666),
        (c.UPDATE_INC, "counters.inc_i", 50),
        (c.UPDATE_DEC, "counters.dec_i", 50),
        (c.UPDATE_APPEND, "list", "world!"),
        (c.UPDATE_REMOVE, "list", "remove"),
        (c.UPDATE_DELETE, "map", "a"),
        (c.UPDATE_SET, "map.b", 99),
    ]
    assert c.update_by_query("bulk_b:true", operations)
    expected.update({})
    assert c.get('bulk_update') == expected
    assert c.get('bulk_update2') == expected


def _test_delete_matching(c: Collection):
    # Test Delete Matching
    key_len = len(list(c.keys()))
    c.delete_matching("delete_b:true")
    c.commit()
    retry_count = 0
    # Leave time for eventually consistent DBs to be in sync
    while key_len - 4 != len(list(c.keys())):
        if retry_count == 5:
            break
        retry_count += 1
        time.sleep(0.5*retry_count)
        c.commit()
    assert key_len - 4 == len(list(c.keys()))


def _test_fields(c: Collection):
    assert c.fields() != {}


TEST_FUNCTIONS = [
    (_test_get, "get"),
    (_test_multiget, "multiget"),
    (_test_keys, "keys"),
    (_test_update, "update"),
    (_test_update_by_query, "update_by_query"),
    (_test_delete_matching, "delete_matching"),
    (_test_fields, "fields")
]


# noinspection PyShadowingNames
@pytest.mark.parametrize("function", [f[0] for f in TEST_FUNCTIONS], ids=[f[1] for f in TEST_FUNCTIONS])
def test_solr(solr_connection: Collection, function):
    if solr_connection:
        function(solr_connection)


# noinspection PyShadowingNames
@pytest.mark.parametrize("function", [f[0] for f in TEST_FUNCTIONS], ids=[f[1] for f in TEST_FUNCTIONS])
def test_es(es_connection: Collection, function):
    if es_connection:
        function(es_connection)


def fix_date(data):
    # making date precision all the same throughout the datastores so we can compared them
    return {k.replace(".000", ""): v for k, v in data.items()}


def compare_output(solr, elastic):
    errors = []

    if solr != elastic:
        errors.append("solr != elastic")

    if errors:
        print("\n\nNot all outputs are equal: {non_equal}\n\n"
              "solr = {solr}\nelastic = {elastic}\n\n".format(non_equal=", ".join(errors),
                                                              solr=solr,
                                                              elastic=elastic))
        return False

    return True


def _test_c_get(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.get('list'), e_tc.get('list'))


def _test_c_require(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.require('string'), e_tc.require('string'))


def _test_c_get_if_exists(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.get_if_exists('int'), e_tc.get_if_exists('int'))


def _test_c_multiget(s_tc: Collection, e_tc: Collection):
    for x in range(5):
        key = 'dict%s' % x
        assert compare_output(s_tc.get(key), e_tc.get(key))
    assert compare_output(s_tc.multiget(['int', 'int']),
                          e_tc.multiget(['int', 'int']))


def _test_c_search(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.search('*:*', sort="id asc"),
                          e_tc.search('*:*', sort="id asc"))
    assert compare_output(s_tc.search('*:*', offset=1, rows=1, filters="lvl_i:400",
                                      sort="id asc", fl='classification_s'),
                          e_tc.search('*:*', offset=1, rows=1, filters="lvl_i:400",
                                      sort="id asc", fl='classification_s'))


def _test_c_deepsearch(s_tc: Collection, e_tc: Collection):
    s_res = []
    deep_paging_id = "*"
    while True:
        s_data = s_tc.search('*:*', rows=5, deep_paging_id=deep_paging_id)
        s_res.extend(s_data['items'])
        if len(s_res) == s_data['total'] or len(s_data['items']) == 0:
            break
        deep_paging_id = s_data['next_deep_paging_id']

    e_res = []
    deep_paging_id = "*"
    while True:
        e_data = e_tc.search('*:*', rows=5, deep_paging_id=deep_paging_id)
        e_res.extend(e_data['items'])
        if len(e_res) == e_data['total'] or len(e_data['items']) == 0:
            break
        deep_paging_id = e_data['next_deep_paging_id']

    assert compare_output(s_res, e_res)


def _test_c_streamsearch(s_tc: Collection, e_tc: Collection):
    ss_s_list = list(s_tc.stream_search('classification_s:*', filters="lvl_i:400", fl='classification_s'))
    ss_e_list = list(e_tc.stream_search('classification_s:*', filters="lvl_i:400", fl='classification_s'))
    assert compare_output(ss_s_list, ss_e_list)


def _test_c_keys(s_tc: Collection, e_tc: Collection):
    assert compare_output(sorted(list(s_tc.keys())), sorted(list(e_tc.keys())))


def _test_c_histogram(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.histogram('lvl_i', 0, 1000, 100, mincount=2),
                          e_tc.histogram('lvl_i', 0, 1000, 100, mincount=2))

    h_s = s_tc.histogram('expiry_dt',
                         '{n}-10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                         '{n}+10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                         '+1{d}'.format(d=s_tc.datastore.day, mincount=2))
    h_e = e_tc.histogram('expiry_dt',
                         '{n}-10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                         '{n}+10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                         '+1{d}'.format(d=e_tc.datastore.day, mincount=2))
    assert compare_output(fix_date(h_s), fix_date(h_e))


def _test_c_facet(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.facet('classification_s'),
                          e_tc.facet('classification_s'))


def _test_c_stats(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.stats('lvl_i'),
                          e_tc.stats('lvl_i'))


def _test_c_group_search(s_tc: Collection, e_tc: Collection):
    assert compare_output(s_tc.grouped_search('lvl_i', fl='classification_s'),
                          e_tc.grouped_search('lvl_i', fl='classification_s'))

    assert compare_output(s_tc.grouped_search('lvl_i', fl='classification_s', offset=1, rows=2,
                                              sort="lvl_i desc"),
                          e_tc.grouped_search('lvl_i', fl='classification_s', offset=1, rows=2,
                                              sort="lvl_i desc"))


def _test_c_fields(s_tc: Collection, e_tc: Collection):
    # For some reason, elasticsearch adds the random list key as a field name. Since this is a
    # specific thing with elasticsearch we will pop that field from the rest and compare the other
    # fields accordingly.
    e_fields = e_tc.fields()
    e_fields.pop('list', None)

    # For non-modeled data, we only want to compare values for indexed, stored, and type field.
    #  ** The default field will always be False because the value is pulled from the model (no need to compare)
    #  ** The list field will always be True in elasticsearch (will always fail if we compare)
    assert compare_output(
        {n: {'indexed': x['indexed'], 'stored': x['stored'], 'type': x['type']} for n, x in s_tc.fields().items()},
        {n: {'indexed': x['indexed'], 'stored': x['stored'], 'type': x['type']} for n, x in e_fields.items()},
    )


TEST_CONSISTENCY_FUNCS = [
    (_test_c_get, "get"),
    (_test_c_require, "require"),
    (_test_c_get_if_exists, "get_if_exists"),
    (_test_c_multiget, "multiget"),
    (_test_c_deepsearch, "deep_search"),
    (_test_c_search, "search"),
    (_test_c_streamsearch, "stream_search"),
    (_test_c_keys, "keys"),
    (_test_c_histogram, "histogram"),
    (_test_c_facet, "facet"),
    (_test_c_stats, "stats"),
    (_test_c_group_search, "group_search"),
    (_test_c_fields, "fields"),

]


# noinspection PyShadowingNames
@pytest.mark.parametrize("function", [f[0] for f in TEST_CONSISTENCY_FUNCS], ids=[f[1] for f in TEST_CONSISTENCY_FUNCS])
def test_consistency(solr_connection: Collection, es_connection: Collection, function):
    if solr_connection and es_connection:
        function(solr_connection, es_connection)
