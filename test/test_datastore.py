import pytest
import random
import string
import time
import warnings

from datemath import dm
from retrying import retry

from assemblyline.datastore import Collection

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    test_map = {
        'test1': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'test1_s': 'hello'},
        'test2': {'expiry_dt': dm('now-1d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 100, 'test2_s': 'hello'},
        'test3': {'expiry_dt': dm('now/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 200, 'test3_s': 'hello'},
        'test4': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'test4_s': 'hello'},
        'dict1': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'classification_s': 'U', 'test1_s': 'hello'},
        'dict2': {'expiry_dt': dm('now/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 100, 'classification_s': 'U', 'test2_s': 'hello'},
        'dict3': {'expiry_dt': dm('now-3d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 200, 'classification_s': 'C', 'test3_s': 'hello'},
        'dict4': {'expiry_dt': dm('now-1d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'classification_s': 'TS', 'test4_s': 'hello'},
        'string': "A string!",
        'list': ['a', 'list', 'of', 'string', 100],
        'int': 69,
        'to_update': {'counters': {'lvl_i': 100, "inc_i": 0, "dec_i": 100}, "list": ['hello', 'remove']},
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

    return pytest.skip("Connection to the SOLR server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def es_connection(request):
    from assemblyline.datastore.stores.es_store import ESStore

    try:
        collection = setup_store(ESStore(['127.0.0.1']), request)
    except SetupException:
        collection = None

    if collection:
        return collection

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def riak_connection(request):
    from assemblyline.datastore.stores.riak_store import RiakStore

    try:
        collection = setup_store(RiakStore(['127.0.0.1']), request)
    except SetupException:
        collection = None

    if collection:
        return collection

    return pytest.skip("Connection to the Riak server failed. This test cannot be performed...")


def _perform_single_datastore_tests(c: Collection):
    # Test GET
    assert test_map.get('test1') == c.get('test1')
    assert test_map.get('test2') == c.get('test2')
    assert test_map.get('test3') == c.get('test3')
    assert test_map.get('test4') == c.get('test4')
    assert test_map.get('string') == c.get('string')
    assert test_map.get('list') == c.get('list')
    assert test_map.get('int') == c.get('int')

    # TEST Multi-get
    raw = [test_map.get('test1'), test_map.get('int'), test_map.get('test2')]
    ds_raw = c.multiget(['test1', 'int', 'test2'])
    for item in ds_raw:
        raw.remove(item)
    assert len(raw) == 0

    # Test KEYS
    test_keys = list(test_map.keys())
    for k in c.keys():
        test_keys.remove(k)
    assert len(test_keys) == 0

    # Test Update
    operations = [
        (c.UPDATE_SET, "counters.lvl_i", 666),
        (c.UPDATE_INC, "counters.inc_i", 50),
        (c.UPDATE_DEC, "counters.dec_i", 50),
        (c.UPDATE_APPEND, "list", "world!"),
        (c.UPDATE_REMOVE, "list", "remove")
    ]
    assert c.update('to_update', operations)
    assert c.get('to_update') == {'counters': {'lvl_i': 666, 'inc_i': 50, 'dec_i': 50}, 'list': ['hello', 'world!']}

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


# noinspection PyShadowingNames
def test_solr(solr_connection: Collection):
    if solr_connection:
        _perform_single_datastore_tests(solr_connection)


# noinspection PyShadowingNames
def test_es(es_connection: Collection):
    if es_connection:
        _perform_single_datastore_tests(es_connection)


# noinspection PyShadowingNames
def test_riak(riak_connection: Collection):
    if riak_connection:
        _perform_single_datastore_tests(riak_connection)


# noinspection PyShadowingNames
def test_datastore_consistency(riak_connection: Collection,
                               solr_connection: Collection,
                               es_connection: Collection):
    if riak_connection and solr_connection and es_connection:

        def fix_date(data):
            # making date precision all the same throughout the datastores so we can compared them
            return {k.replace(".000", ""): v for k, v in data.items()}

        def fix_ids(data):
            # We're remapping all id fields to a default value so we can compare outputs
            data['items'] = [{'ID' if k in ["_id", '_yz_rk', '_id_'] else k: v
                              for k, v in item.items()}
                             for item in data['items']]
            return data

        def compare_output(solr, elastic, riak):
            errors = []

            if solr != riak:
                errors.append("solr != riak")

            if solr != elastic:
                errors.append("solr != elastic")

            if elastic != riak:
                errors.append("elastic != riak")

            if errors:
                print("\n\nNot all outputs are equal: {non_equal}\n\n"
                      "solr = {solr}\nelastic = {elastic}\nriak = {riak}\n\n".format(non_equal=", ".join(errors),
                                                                                     solr=solr,
                                                                                     elastic=elastic,
                                                                                     riak=riak))
                return False

            return True

        stores = {}
        s_tc = stores['solr'] = solr_connection
        e_tc = stores['elastic'] = es_connection
        r_tc = stores['riak'] = riak_connection

        assert compare_output(s_tc.get('list'), e_tc.get('list'), r_tc.get('list'))
        assert compare_output(s_tc.require('string'), e_tc.require('string'), r_tc.require('string'))
        assert compare_output(s_tc.get_if_exists('int'), e_tc.get_if_exists('int'), r_tc.get_if_exists('int'))
        for x in range(5):
            key = 'dict%s' % x
            assert compare_output(s_tc.get(key), e_tc.get(key), r_tc.get(key))
        assert compare_output(s_tc.multiget(['int', 'int']),
                              e_tc.multiget(['int', 'int']),
                              r_tc.multiget(['int', 'int']))
        assert compare_output(fix_ids(s_tc.search('*:*', sort="%s asc" % s_tc.datastore.ID)),
                              fix_ids(e_tc.search('*:*', sort="%s asc" % e_tc.datastore.ID)),
                              fix_ids(r_tc.search('*:*', sort="%s asc" % r_tc.datastore.ID)))
        assert compare_output(s_tc.search('*:*', offset=1, rows=1, filters="lvl_i:400",
                                          sort="%s asc" % s_tc.datastore.ID, fl='classification_s'),
                              e_tc.search('*:*', offset=1, rows=1, filters="lvl_i:400",
                                          sort="%s asc" % e_tc.datastore.ID, fl='classification_s'),
                              r_tc.search('*:*', offset=1, rows=1, filters="lvl_i:400",
                                          sort="%s asc" % r_tc.datastore.ID, fl='classification_s'))
        ss_s_list = list(s_tc.stream_search('classification_s:*', filters="lvl_i:400", fl='classification_s'))
        ss_e_list = list(e_tc.stream_search('classification_s:*', filters="lvl_i:400", fl='classification_s'))
        ss_r_list = list(r_tc.stream_search('classification_s:*', filters="lvl_i:400", fl='classification_s'))
        assert compare_output(ss_s_list, ss_e_list, ss_r_list)

        assert compare_output(sorted(list(s_tc.keys())), sorted(list(e_tc.keys())), sorted(list(r_tc.keys())))
        assert compare_output(s_tc.histogram('lvl_i', 0, 1000, 100, mincount=2),
                              e_tc.histogram('lvl_i', 0, 1000, 100, mincount=2),
                              r_tc.histogram('lvl_i', 0, 1000, 100, mincount=2))

        h_s = s_tc.histogram('expiry_dt',
                             '{n}-10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                             '+1{d}'.format(d=s_tc.datastore.day, mincount=2))
        h_e = e_tc.histogram('expiry_dt',
                             '{n}-10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                             '+1{d}'.format(d=e_tc.datastore.day, mincount=2))
        h_r = r_tc.histogram('expiry_dt',
                             '{n}-10{d}/{d}'.format(n=r_tc.datastore.now, d=r_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=r_tc.datastore.now, d=r_tc.datastore.day),
                             '+1{d}'.format(d=r_tc.datastore.day, mincount=2))
        assert compare_output(fix_date(h_s), fix_date(h_e), fix_date(h_r))
        assert compare_output(s_tc.field_analysis('classification_s'),
                              e_tc.field_analysis('classification_s'),
                              r_tc.field_analysis('classification_s'))

        assert compare_output(s_tc.grouped_search('lvl_i', fl='classification_s'),
                              e_tc.grouped_search('lvl_i', fl='classification_s'),
                              r_tc.grouped_search('lvl_i', fl='classification_s'))

        assert compare_output(s_tc.grouped_search('lvl_i', fl='classification_s', offset=1, rows=2,
                                                  sort="lvl_i desc"),
                              e_tc.grouped_search('lvl_i', fl='classification_s', offset=1, rows=2,
                                                  sort="lvl_i desc"),
                              r_tc.grouped_search('lvl_i', fl='classification_s', offset=1, rows=2,
                                                  sort="lvl_i desc"))

        # TODO: fields are not of the same type in-between datastores does that matter?
        #       will print output for now without failing the test
        compare_output(s_tc.fields(), e_tc.fields(), r_tc.fields())
