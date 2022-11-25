import random
import string
import warnings
import uuid

from copy import copy
from datemath import dm
from retrying import retry
import pytest

from assemblyline.datastore.collection import ESCollection, Index
from assemblyline.datastore.exceptions import VersionConflictException


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    test_map = {
        'test1': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'test1_s': 'hello', 'tags_ss': ['a', 'b', 'c'], 'from_archive': False},
        'test2': {'expiry_dt': dm('now-1d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 100, 'test2_s': 'hello', 'tags_ss': ['a', 'b', 'f'], 'from_archive': False},
        'test3': {'expiry_dt': dm('now/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 200, 'test3_s': 'hello', 'tags_ss': ['a', 'b', 'e'], 'from_archive': False},
        'test4': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'test4_s': 'hello', 'tags_ss': ['a', 'b', 'd'], 'from_archive': False},
        'dict1': {'expiry_dt': dm('now-2d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'classification_s': 'U', 'test1_s': 'hello', 'tags_ss': [], 'from_archive': False},
        'dict2': {'expiry_dt': dm('now/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 100, 'classification_s': 'U', 'test2_s': 'hello', 'tags_ss': [], 'from_archive': False},
        'dict3': {'expiry_dt': dm('now-3d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 200, 'classification_s': 'C', 'test3_s': 'hello', 'tags_ss': [], 'from_archive': False},
        'dict4': {'expiry_dt': dm('now-1d/m').isoformat().replace('+00:00', '.001Z'),
                  'lvl_i': 400, 'classification_s': 'TS', 'test4_s': 'hello', 'tags_ss': [], 'from_archive': False},
        'string': "A string!",
        'list': ['a', 'list', 'of', 'string', 100],
        'int': 69,
        'to_update': {
            'counters': {
                'lvl_i': 100,
                "inc_i": 0,
                "dec_i": 100
            },
            "list": ['hello', 'remove'],
            "map": {
                'a': 1
            }
        },
        'bulk_update': {'bulk_b': True, "map": {'a': 1}, 'counters': {
            'lvl_i': 100, "inc_i": 0, "dec_i": 100}, "list": ['hello', 'remove'], 'from_archive': False},
        'bulk_update2': {'bulk_b': True, "map": {'a': 1}, 'counters': {
            'lvl_i': 100, "inc_i": 0, "dec_i": 100}, "list": ['hello', 'remove'], 'from_archive': False},
        'delete1': {'delete_b': True, 'lvl_i': 100, 'from_archive': False},
        'delete2': {'delete_b': True, 'lvl_i': 300, 'from_archive': False},
        'delete3': {'delete_b': True, 'lvl_i': 400, 'from_archive': False},
        'delete4': {'delete_b': True, 'lvl_i': 200, 'from_archive': False},
        'archive1': {'data': "This is archive 1 data", 'from_archive': False},
        'archive2': {'data': "This is archive 2 data", 'from_archive': False},
        'archive3': {'data': "This is archive 3 data", 'from_archive': False},
        'archive4': {'data': "This is archive 4 data", 'from_archive': False}
    }


class SetupException(Exception):
    pass


@retry(stop_max_attempt_number=10, wait_random_min=100, wait_random_max=500)
def setup_store(docstore, request):
    try:
        ret_val = docstore.ping()
        if ret_val:
            collection_name = ''.join(random.choices(string.ascii_lowercase, k=10))

            # Give achive access
            docstore.archive_indices.append(collection_name)

            docstore.register(collection_name)
            collection = docstore.__getattr__(collection_name)

            # create special finalizer
            def cleanup():
                collection.wipe(recreate=False)

            request.addfinalizer(cleanup)

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
def es_connection(request):
    from assemblyline.datastore.store import ESStore

    try:
        collection = setup_store(ESStore(['http://elastic:devpass@127.0.0.1:9200']), request)
    except SetupException:
        collection = None

    if collection:
        return collection

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


def _test_archive(c: ESCollection):
    # Test GET
    assert c.archive('archive1', delete_after=True)
    assert c.archive('archive2')
    assert c.get_if_exists('archive1')['from_archive']
    assert not c.exists('archive1', index_type=Index.HOT)
    assert not c.get_if_exists('archive2')['from_archive']
    assert c.get_if_exists('archive2', index_type=Index.ARCHIVE)['from_archive']


def _test_archive_by_query(c: ESCollection):
    # Test GET
    assert c.archive_by_query("_id:archive3 OR _id:archive4")

    # Are the docs archived?
    assert c.get_if_exists('archive3', index_type=Index.ARCHIVE)['from_archive']
    assert c.exists('archive4', index_type=Index.ARCHIVE)

    # Are they still in hot?
    assert not c.get_if_exists('archive3', index_type=Index.HOT)['from_archive']
    assert c.exists('archive4', index_type=Index.HOT)


def _test_bulk(c: ESCollection):
    delete_plan = c.get_bulk_plan()
    delete_plan.add_delete_operation('test1')
    delete_plan.add_delete_operation('test2')
    delete_plan.add_delete_operation('test3')
    delete_plan.add_delete_operation('test4')
    c.bulk(delete_plan)

    assert not c.exists('test1')
    assert not c.exists('test2')
    assert not c.exists('test3')
    assert not c.exists('test4')

    insert_plan = c.get_bulk_plan(index_type=Index.HOT)
    insert_plan.add_insert_operation('test1', test_map.get('test1'))
    insert_plan.add_insert_operation('test2', test_map.get('test2'))
    insert_plan.add_insert_operation('test3', test_map.get('test3'))
    insert_plan.add_insert_operation('test4', test_map.get('test4'))
    c.bulk(insert_plan)

    assert c.exists('test1')
    assert c.exists('test2')
    assert c.exists('test3')
    assert c.exists('test4')


def _test_exists(c: ESCollection):
    # Test GET
    assert c.exists('test1')
    assert c.exists('test2')
    assert c.exists('test3')
    assert c.exists('test4')
    assert c.exists('string')
    assert c.exists('list')
    assert c.exists('int')


def _test_get(c: ESCollection):
    # Test GET
    assert test_map.get('test1') == c.get('test1')
    assert test_map.get('test2') == c.get('test2')
    assert test_map.get('test3') == c.get('test3')
    assert test_map.get('test4') == c.get('test4')
    assert test_map.get('string') == c.get('string')
    assert test_map.get('list') == c.get('list')
    assert test_map.get('int') == c.get('int')


def _test_require(c: ESCollection):
    # Test GET
    assert test_map.get('test1') == c.require('test1')
    assert test_map.get('test2') == c.require('test2')
    assert test_map.get('test3') == c.require('test3')
    assert test_map.get('test4') == c.require('test4')
    assert test_map.get('string') == c.require('string')
    assert test_map.get('list') == c.require('list')
    assert test_map.get('int') == c.require('int')


def _test_get_if_exists(c: ESCollection):
    # Test GET
    assert test_map.get('test1') == c.get_if_exists('test1')
    assert test_map.get('test2') == c.get_if_exists('test2')
    assert test_map.get('test3') == c.get_if_exists('test3')
    assert test_map.get('test4') == c.get_if_exists('test4')
    assert test_map.get('string') == c.get_if_exists('string')
    assert test_map.get('list') == c.get_if_exists('list')
    assert test_map.get('int') == c.get_if_exists('int')


def _test_multiget(c: ESCollection):
    # TEST Multi-get
    raw = [test_map.get('test1'), test_map.get('int'), test_map.get('test2')]
    ds_raw = c.multiget(['test1', 'int', 'test2'], as_dictionary=False)
    for item in ds_raw:
        raw.remove(item)
    assert len(raw) == 0

    for k, v in c.multiget(['test1', 'int', 'test2'], as_dictionary=True).items():
        assert test_map[k] == v

    assert c.multiget([]) == {}


def _test_multiexists(c: ESCollection):
    # Test GET
    assert all(c.multiexists(['test1', 'test2', 'test3', 'test4', 'string', 'list', 'int']).values())


def _test_keys(c: ESCollection):
    # Test KEYS
    test_keys = list(test_map.keys())
    for k in c.keys(index_type=Index.HOT_AND_ARCHIVE):
        if k in test_keys:
            test_keys.remove(k)
    assert len(test_keys) == 0


def _test_update(c: ESCollection):
    # Test Update
    expected = {
        'counters': {'lvl_i': 666, 'inc_i': 50, 'dec_i': 50},
        'list': ['hello', 'world!', 'test_if_missing'],
        "map": {'b': 99},
        'from_archive': False
    }
    operations = [
        (c.UPDATE_SET, "counters.lvl_i", 666),
        (c.UPDATE_INC, "counters.inc_i", 50),
        (c.UPDATE_DEC, "counters.dec_i", 50),
        (c.UPDATE_APPEND, "list", "world!"),
        (c.UPDATE_APPEND_IF_MISSING, "list", "test_if_missing"),
        (c.UPDATE_APPEND_IF_MISSING, "list", "world!"),
        (c.UPDATE_REMOVE, "list", "remove"),
        (c.UPDATE_DELETE, "map", "a"),
        (c.UPDATE_SET, "map.b", 99),
    ]
    assert c.update('to_update', operations)
    assert c.get('to_update') == expected


def _test_update_by_query(c: ESCollection):
    # Test update_by_query
    expected = {
        'bulk_b': True,
        'counters': {
            'lvl_i': 666,
            'inc_i': 50,
            'dec_i': 50},
        'list': ['hello', 'world!', 'test_if_missing'],
        "map": {'b': 99},
        'from_archive': False
    }
    operations = [
        (c.UPDATE_SET, "counters.lvl_i", 666),
        (c.UPDATE_INC, "counters.inc_i", 50),
        (c.UPDATE_DEC, "counters.dec_i", 50),
        (c.UPDATE_APPEND, "list", "world!"),
        (c.UPDATE_APPEND_IF_MISSING, "list", "test_if_missing"),
        (c.UPDATE_APPEND_IF_MISSING, "list", "world!"),
        (c.UPDATE_REMOVE, "list", "remove"),
        (c.UPDATE_DELETE, "map", "a"),
        (c.UPDATE_SET, "map.b", 99),
    ]
    assert c.update_by_query("bulk_b:true", operations)
    expected.update({})
    assert c.get('bulk_update') == expected
    assert c.get('bulk_update2') == expected


def _test_delete_by_query(c: ESCollection):
    # Make sure other tests don't interfere
    c.commit()
    key_len = len(list(c.keys()))
    deleted = c.delete_by_query("delete_b:true")

    # Make sure deletes are permanent
    c.commit()

    # Test
    assert deleted > 0
    assert key_len - deleted == len(list(c.keys()))


def _test_fields(c: ESCollection):
    assert c.fields() != {}


def _test_search(c: ESCollection):
    for item in c.search('*:*', sort="id asc")['items']:
        assert item['id'][0] in test_map
    for item in c.search('*:*', offset=1, rows=1,
                         filters="lvl_i:400", sort="id asc", fl='id,classification_s')['items']:
        assert item['id'][0] in test_map
        assert item.get('classification_s', None) is not None


def _test_group_search(c: ESCollection):
    gs_simple = c.grouped_search('lvl_i', fl='classification_s')
    assert gs_simple['offset'] == 0
    assert gs_simple['rows'] == 25
    assert gs_simple['total'] == 8
    assert len(gs_simple['items']) == 3
    total = 0
    for item in gs_simple['items']:
        assert 'value' in item
        assert isinstance(item['value'], int)
        assert 'total' in item
        assert isinstance(item['total'], int)
        assert 'items' in item
        assert isinstance(item['items'], list)
        total += item['total']
    assert total == gs_simple['total']

    gs_complex = c.grouped_search('lvl_i', fl='classification_s', offset=1, rows=2, sort="lvl_i desc")
    assert gs_complex['offset'] == 1
    assert gs_complex['rows'] == 2
    assert gs_complex['total'] == 8
    assert len(gs_complex['items']) == 2
    total = 0
    for item in gs_complex['items']:
        assert 'value' in item
        assert isinstance(item['value'], int)
        assert 'total' in item
        assert isinstance(item['total'], int)
        assert 'items' in item
        assert isinstance(item['items'], list)
        total += item['total']
    assert total <= gs_complex['total']


def _test_deepsearch(c: ESCollection):
    res = []
    deep_paging_id = "*"
    while deep_paging_id:
        s_data = c.search('*:*', rows=5, deep_paging_id=deep_paging_id)
        res.extend(s_data['items'])
        deep_paging_id = s_data.get('next_deep_paging_id', None)

    assert len(res) == c.search('*:*', sort="id asc")['total']
    for item in res:
        assert item['id'][0] in test_map


def _test_streamsearch(c: ESCollection):
    items = list(c.stream_search('classification_s:*', filters="lvl_i:400", fl='id,classification_s'))
    assert len(items) > 0
    for item in items:
        assert item['id'][0] in test_map
        assert item.get('classification_s', None) is not None


def _test_histogram(c: ESCollection):
    h_int = c.histogram('lvl_i', 0, 1000, 100, mincount=2)
    assert len(h_int) > 0
    for k, v in h_int.items():
        assert isinstance(k, int)
        assert isinstance(v, int)
        assert v > 0

    h_date = c.histogram('expiry_dt', '{n}-10{d}/{d}'.format(n=c.datastore.now, d=c.datastore.day),
                         '{n}+10{d}/{d}'.format(n=c.datastore.now, d=c.datastore.day),
                         '+1{d}'.format(d=c.datastore.day), mincount=2)
    assert len(h_date) > 0
    for k, v in h_date.items():
        assert isinstance(k, str)
        assert "T00:00:00" in k
        assert k.endswith("Z")
        assert isinstance(v, int)
        assert v > 0


def _test_facet(c: ESCollection):
    facets = c.facet('classification_s')
    assert len(facets) > 0
    for k, v in facets.items():
        assert k in ["U", "C", "TS"]
        assert isinstance(v, int)
        assert v > 0


def _test_stats(c: ESCollection):
    stats = c.stats('lvl_i')
    assert len(stats) > 0
    for k, v in stats.items():
        assert k in ['count', 'min', 'max', 'avg', 'sum']
        assert isinstance(v, (int, float))
        assert v > 0


def _test_fix_shards(c: ESCollection):
    def get_current_shard_values(alias):
        current_settings = c.with_retries(c.datastore.client.indices.get_settings, index=alias)
        index_settings = current_settings.get(c._get_current_alias(alias))
        return int(index_settings['settings']['index']['number_of_shards'])

    # Test hot index
    c.shards = 2
    c.fix_shards(index_type=Index.HOT)
    assert get_current_shard_values(c.name) == 2

    # Test archive index
    c.archive_shards = 2
    c.fix_shards(index_type=Index.ARCHIVE)
    assert get_current_shard_values(c.archive_name) == 2

    # Reset shards
    c.shards = 1
    c.archive_shards = 1
    c.fix_shards(index_type=Index.HOT_AND_ARCHIVE)
    assert get_current_shard_values(c.name) == 1
    assert get_current_shard_values(c.archive_name) == 1


def _test_fix_replicas(c: ESCollection):
    def get_current_replicas_values(alias):
        current_settings = c.with_retries(c.datastore.client.indices.get_settings, index=alias)
        index_settings = current_settings.get(c._get_current_alias(alias))
        return int(index_settings['settings']['index']['number_of_replicas'])

    # Test hot index
    c.replicas = 1
    c.fix_replicas(index_type=Index.HOT)
    assert get_current_replicas_values(c.name) == 1

    # Test archive index
    c.archive_replicas = 1
    c.fix_replicas(index_type=Index.ARCHIVE)
    assert get_current_replicas_values(c.archive_name) == 1

    # Reset shards
    c.replicas = 0
    c.archive_replicas = 0
    c.fix_replicas(index_type=Index.HOT_AND_ARCHIVE)
    assert get_current_replicas_values(c.name) == 0
    assert get_current_replicas_values(c.archive_name) == 0


def _test_reindex(c: ESCollection):
    previous_keys = list(c.keys(index_type=Index.HOT_AND_ARCHIVE))
    c.reindex()
    c.commit()
    new_keys = list(c.keys(index_type=Index.HOT_AND_ARCHIVE))

    assert sorted(previous_keys) == sorted(new_keys)


def _test_save(c: ESCollection):
    key = "save_test"
    doc = {"data": "saved_doc"}

    def expected_doc(doc, archive):
        new_doc = copy(doc)
        new_doc['from_archive'] = archive
        return new_doc

    # Test save hot
    assert c.save(key, doc)
    assert c.exists(key)
    assert c.get_if_exists(key) == expected_doc(doc, False)
    assert not c.exists(key, index_type=Index.ARCHIVE)

    # Test searchability
    c.commit()
    assert c.search('data:saved_doc', fl='data,from_archive')['items'][0] == expected_doc(doc, False)

    # Cleanup
    c.delete(key)
    c.commit()

    # Test save archive
    assert c.save(key, doc, index_type=Index.ARCHIVE)
    assert c.exists(key, index_type=Index.ARCHIVE)
    assert c.get_if_exists(key, index_type=Index.ARCHIVE) == expected_doc(doc, True)
    assert not c.exists(key, index_type=Index.HOT)

    # Test searchability
    c.commit()
    assert c.search('data:saved_doc', fl='data,from_archive',
                    index_type=Index.ARCHIVE)['items'][0] == expected_doc(doc, True)

    # Cleanup
    c.delete(key)
    c.commit()

    # Test save both
    assert c.save(key, doc, index_type=Index.HOT_AND_ARCHIVE)
    assert c.exists(key, index_type=Index.ARCHIVE)
    assert c.exists(key, index_type=Index.HOT)
    assert c.get_if_exists(key, index_type=Index.ARCHIVE) == expected_doc(doc, True)
    assert c.get_if_exists(key, index_type=Index.HOT) == expected_doc(doc, False)

    # Test searchability
    c.commit()
    assert c.search('data:saved_doc', fl='data,from_archive',
                    index_type=Index.ARCHIVE)['items'][0] == expected_doc(doc, True)
    assert c.search('data:saved_doc', fl='data,from_archive',
                    index_type=Index.HOT)['items'][0] == expected_doc(doc, False)

    # Cleanup
    c.delete(key)
    c.commit()


TEST_FUNCTIONS = [
    (_test_archive, "archive"),
    (_test_archive_by_query, "archive_by_query"),
    (_test_bulk, "bulk"),
    (_test_exists, "exists"),
    (_test_get, "get"),
    (_test_require, "require"),
    (_test_get_if_exists, "get_if_exists"),
    (_test_multiexists, "multiexists"),
    (_test_multiget, "multiget"),
    (_test_keys, "keys"),
    (_test_update, "update"),
    (_test_update_by_query, "update_by_query"),
    (_test_delete_by_query, "delete_by_query"),
    (_test_fields, "fields"),
    (_test_search, "search"),
    (_test_group_search, "group_search"),
    (_test_deepsearch, "deepsearch"),
    (_test_streamsearch, "streamsearch"),
    (_test_histogram, "histogram"),
    (_test_facet, "facet"),
    (_test_stats, "stats"),
    (_test_save, "save"),
    (_test_reindex, "reindex"),
    (_test_fix_replicas, "fix_replicas"),
    (_test_fix_shards, "fix_shards"),
]


# noinspection PyShadowingNames
@pytest.mark.parametrize("function", [f[0] for f in TEST_FUNCTIONS], ids=[f[1] for f in TEST_FUNCTIONS])
def test_es(es_connection: ESCollection, function):
    if es_connection:
        function(es_connection)


def test_atomic_save(es_connection: ESCollection):
    """Save a new document atomically, then try to save it again and detect the failure."""
    unique_id = uuid.uuid4().hex
    data = {
        'id': unique_id,
        'cats': 'good'
    }

    # Verify the document is new
    no_data, version = es_connection.get_if_exists(unique_id, as_obj=False, version=True)
    assert no_data is None
    assert version is not None

    # Save atomically with version set
    es_connection.save(unique_id, data, version=version)

    # Make sure we can't save again with the same 'version'
    with pytest.raises(VersionConflictException):
        es_connection.save(unique_id, data, version=version)

    # Get the data, which exists now
    new_data, version = es_connection.get_if_exists(unique_id, as_obj=False, version=True)
    assert new_data is not None

    # Overwrite with real version
    es_connection.save(unique_id, data, version=version)

    # But it should only work once
    with pytest.raises(VersionConflictException):
        es_connection.save(unique_id, data, version=version)
