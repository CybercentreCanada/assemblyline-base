import logging
import os

import pytest
import random
import string
import warnings

from datemath import dm
from retrying import retry

from assemblyline import odm
from assemblyline.datastore import log, SearchException
from assemblyline.common.testing import skip

log.setLevel(logging.INFO)
yml_config = os.path.join(os.path.dirname(__file__), "classification.yml")


@odm.model(index=True, store=True)
class ThingsModel(odm.Model):
    count = odm.Integer()
    thing = odm.Text()


@odm.model(index=True, store=True)
class MeasurementModel(odm.Model):
    depth = odm.Integer()
    width = odm.Integer()


@odm.model(index=True, store=True)
class Position(odm.Model):
    x = odm.Integer()
    y = odm.Integer()


@odm.model(index=True, store=True)
class BaseTestModel(odm.Model):
    classification = odm.Classification(default="UNRESTRICTED", yml_config=yml_config)
    flavour = odm.Text(copyto='features', default="EMPTY")
    height = odm.Integer()
    no_store = odm.Optional(odm.Keyword(store=False))
    no_index = odm.Optional(odm.Keyword(index=False, store=False))
    dots = odm.Mapping(odm.Compound(Position), default={})
    birthday = odm.Date()
    tags = odm.List(odm.Enum({'silly', 'cats', '10'}), default=[], copyto='features')
    size = odm.Compound(MeasurementModel, default={'depth': 100, 'width': 100})
    features = odm.List(odm.Text(), default=[])
    metadata = odm.Mapping(odm.Text(), default={})
    things = odm.List(odm.Compound(ThingsModel), default=[])


def safe_date(pattern):
    return dm(f'{pattern}/m').isoformat().replace('+00:00', '.001Z')


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    test_map = {
        'test1': BaseTestModel(dict(tags=['silly'], flavour='chocolate', height=100, birthday=safe_date('now-2d'),
                                    metadata={'url': 'google.com'}, things=[{'count': 1, 'thing': 'hat'}],
                                    classification="RESTRICTED")),
        'test2': BaseTestModel(dict(tags=['cats'], flavour='A little dry', height=180, birthday=safe_date('now-1d'),
                                    metadata={'url': 'google.ca'})),
        'test3': BaseTestModel(dict(tags=['silly'], flavour='Red', height=140, birthday=safe_date('now'),
                                    size={'depth': 1, 'width': 1}, things=[{'count': 1, 'thing': 'hat'},
                                                                           {'count': 10, 'thing': 'shoe'}],
                                    classification="RESTRICTED")),
        'test4': BaseTestModel(dict(tags=['cats'], flavour='Bugs ++', height=30, birthday='2018-10-30T17:48:48.123Z')),
        'dict1': BaseTestModel(dict(tags=['cats'], flavour='A--', height=300, birthday='2018-10-30T17:48:48.123Z')),
        'dict2': BaseTestModel(dict(tags=[], flavour='100%', height=90, birthday=safe_date('now'),
                                    metadata={'origin': 'space'})),
        'dict3': BaseTestModel(dict(tags=['10', 'cats'], flavour='', height=180, birthday=safe_date('now-3d'),
                                    classification="RESTRICTED")),
        'dict4': BaseTestModel(dict(tags=['10', 'silly', 'cats'], flavour='blue', height=100,
                                    birthday=safe_date('now-1d'))),
        'extra1': BaseTestModel(dict(tags=['10'], flavour="delicious", height=300, birthday=safe_date('now-1h'),
                                     no_index="nidx1", no_store="nsto1", dots={'first': {"x": 111, "y": 222}})),
        'extra2': BaseTestModel(dict(tags=['silly', '10'], flavour="delicious", height=400,
                                     birthday=safe_date('now-2h'), no_index="nidx2", no_store="nsto2")),
        'extra3': BaseTestModel(dict(tags=['10', 'silly', 'cats'], flavour="delicious", height=500,
                                     birthday=safe_date('now-3h'), no_index="nidx3", no_store="nsto3",
                                     dots={'first': {"x": 123, "y": 456}, 'second': {"x": 222, "y": 333}})),
        'extra4': BaseTestModel(dict(tags=['cats'], flavour="delicious", height=600, birthday=safe_date('now-4h'),
                                     no_index="nidx4", no_store="nsto4"))
    }


class SetupException(Exception):
    pass


@retry(stop_max_attempt_number=10, wait_random_min=100, wait_random_max=500)
def setup_store(docstore, request):
    try:
        ret_val = docstore.ping()
        if ret_val:
            collection_name = ''.join(random.choices(string.ascii_lowercase, k=10))
            docstore.register(collection_name, BaseTestModel)
            docstore.register(collection_name, BaseTestModel)
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


def get_obj(obj_map, key, as_obj):
    obj = obj_map.get(key)
    if not as_obj:
        return obj.as_primitives()
    return obj


def _test_get(col, as_obj):
    for x in range(1, 4):
        assert get_obj(test_map, f'test{x}', as_obj) == col.get(f'test{x}', as_obj=as_obj)

    for x in range(1, 4):
        assert get_obj(test_map, f'dict{x}', as_obj) == col.get(f'dict{x}', as_obj=as_obj)

    for x in range(1, 4):
        assert get_obj(test_map, f'extra{x}', as_obj) == col.get(f'extra{x}', as_obj=as_obj)

    assert col.get('string', as_obj=as_obj) is None
    assert col.get('list', as_obj=as_obj) is None
    assert col.get('int', as_obj=as_obj) is None


def _test_get_primitives(col, _):
    # Test is as_obj=False is equivalent to as_primitives function
    assert col.get('test1', as_obj=False) == col.get('test1').as_primitives()


def _test_mget(col, as_obj):
    raw = [
        get_obj(test_map, 'test1', as_obj),
        get_obj(test_map, 'dict1', as_obj),
        get_obj(test_map, 'test2', as_obj),
        get_obj(test_map, 'extra3', as_obj)
    ]
    ds_raw = col.multiget(['test1', 'dict1', 'test2', 'extra3'], as_dictionary=False, as_obj=as_obj)
    for item in ds_raw:
        raw.remove(item)
    assert len(raw) == 0

    for k, v in col.multiget(['test1', 'dict1', 'test2', 'extra3'], as_obj=as_obj).items():
        assert get_obj(test_map, k, as_obj) == v

    with pytest.raises(KeyError) as error_info:
        print(col.multiget(['not-a-key-1', 'not-a-key-2'], as_obj=as_obj))
    assert 'not-a-key' in str(error_info.value)


def _test_keys(col, _):
    test_keys = list(test_map.keys())
    for k in col.keys():
        test_keys.remove(k)
    assert len(test_keys) == 0


def _test_search(col, as_obj):
    t1 = col.search('*:*', sort="id asc", as_obj=as_obj)
    assert len(t1['items']) == t1['total']

    # reading list fields on a search
    t2 = col.search('id:dict3', as_obj=as_obj)['items'][0]
    t3 = col.search('id:dict4', as_obj=as_obj)['items'][0]
    if as_obj:
        assert len(t2.tags) == 2
        assert len(t3.tags) == 3
    else:
        assert len(t2['tags']) == 2
        assert len(t3['tags']) == 3

    # reading single fields on a search
    t4 = col.search('id:test1', as_obj=as_obj)['items'][0]
    if as_obj:
        assert t4.flavour == 'chocolate'
    else:
        assert t4['flavour'] == 'chocolate'

    # Make sure sorting on the ID key works right
    forward = col.search('*', sort='id asc', as_obj=as_obj)
    reverse = col.search('*', sort='id desc', as_obj=as_obj)
    assert forward['items'] == list(reversed(reverse['items']))

    # Search on a copyto field
    assert col.search('features:chocolate', as_obj=as_obj)['total'] == 1

    # Make sure we are getting only the expected fields with a field list
    result = col.search('features:chocolate', fl='features', as_obj=as_obj)
    assert result['total'] == 1
    if as_obj:
        with pytest.raises(odm.KeyMaskException):
            _ = result['items'][0].flavour
    else:
        with pytest.raises(KeyError):
            _ = result['items'][0]['flavour']

    # Check that the metadata is searchable
    assert col.search('metadata.url:*google*', as_obj=as_obj)['total'] == 2
    assert col.search('classification:RESTRICTED', as_obj=as_obj)['total'] == 3

    # Testing non indexed and non stored fields
    try:
        res = col.search('no_index:nidx*', as_obj=as_obj)
    except SearchException:
        res = {'total': 0}

    assert res['total'] == 0
    assert col.search('no_store:nsto*', as_obj=as_obj)['total'] == 4


def _test_search_primitives(col, _):
    # Make sure as_obj=False produces the same result then obj.as_primitives()
    obj_item = col.search('features:chocolate', fl='features')['items'][0]
    dict_item = col.search('features:chocolate', fl='features', as_obj=False)['items'][0]
    assert obj_item.as_primitives() == dict_item


TEST_FUNCTIONS = [
    (_test_get, True, "get - object"),
    (_test_get, False, "get - dict"),
    (_test_get_primitives, None, "get primitives"),
    (_test_mget, True, "multiget - object"),
    (_test_mget, False, "multiget - dict"),
    (_test_keys, None, "keys"),
    (_test_search, True, "search - object"),
    (_test_search, False, "search - dict"),
    (_test_search_primitives, None, "search primitives"),
]


# noinspection PyShadowingNames
@pytest.mark.parametrize("function,as_obj", [(f[0], f[1]) for f in TEST_FUNCTIONS], ids=[f[2] for f in TEST_FUNCTIONS])
def test_solr(solr_connection, function, as_obj):
    function(solr_connection, as_obj)


# noinspection PyShadowingNames
@pytest.mark.parametrize("function,as_obj", [(f[0], f[1]) for f in TEST_FUNCTIONS], ids=[f[2] for f in TEST_FUNCTIONS])
def test_es(es_connection, function, as_obj):
    function(es_connection, as_obj)


def fix_date(data):
    # making date precision all the same throughout the datastores so we can compared them
    return {k.replace(".000", ""): v for k, v in data.items()}


def compare_output(solr, elastic):
    errors = []

    try:
        if solr != elastic:
            errors.append("solr != elastic")
    except odm.KeyMaskException:
        errors.append("solr != elastic")

    if errors:
        print("\n\nNot all outputs are equal: {non_equal}\n\n"
              "solr = {solr}\nelastic = {elastic}\n\n".format(non_equal=", ".join(errors),
                                                                             solr=solr,
                                                                             elastic=elastic))
        return False

    return True


def _test_c_get(s_tc, e_tc, as_obj):
    # non-existant object
    assert compare_output(s_tc.get('not-a-key', as_obj=as_obj),
                          e_tc.get('not-a-key', as_obj=as_obj))
    # non-existant object (fast)
    assert compare_output(s_tc.get_if_exists('not-a-key', as_obj=as_obj),
                          e_tc.get_if_exists('not-a-key', as_obj=as_obj))

    # Existing object
    assert compare_output(s_tc.get('test1', as_obj=as_obj),
                          e_tc.get('test1', as_obj=as_obj))

    assert compare_output(s_tc.require('test1', as_obj=as_obj),
                          e_tc.require('test1', as_obj=as_obj))

    assert compare_output(s_tc.get_if_exists('test1', as_obj=as_obj),
                          e_tc.get_if_exists('test1', as_obj=as_obj))

    for x in range(5):
        key = 'dict%s' % x
        assert compare_output(s_tc.get(key, as_obj=as_obj),
                              e_tc.get(key, as_obj=as_obj))


def _test_c_mget(s_tc, e_tc, as_obj):
    assert compare_output(s_tc.multiget(['test1', 'test1'], as_obj=as_obj),
                          e_tc.multiget(['test1', 'test1'], as_obj=as_obj))


def _test_c_search(s_tc, e_tc, as_obj):
    assert compare_output(s_tc.search('*:*', sort="id asc", as_obj=as_obj),
                          e_tc.search('*:*', sort="id asc", as_obj=as_obj))
    assert compare_output(s_tc.search('*:*', offset=1, rows=1, filters="height:100",
                                      sort="id asc", fl='flavour', as_obj=as_obj),
                          e_tc.search('*:*', offset=1, rows=1, filters="height:100",
                                      sort="id asc", fl='flavour', as_obj=as_obj))


def _test_c_streamsearch(s_tc, e_tc, as_obj):
    ss_s_list = list(s_tc.stream_search('flavour:*', filters="height:[30 TO 400]", fl='flavour', as_obj=as_obj))
    ss_e_list = list(e_tc.stream_search('flavour:*', filters="height:[30 TO 400]", fl='flavour', as_obj=as_obj))
    assert compare_output(ss_s_list, ss_e_list)


def _test_c_keys(s_tc, e_tc, _):
    assert compare_output(sorted(list(s_tc.keys())), sorted(list(e_tc.keys())))


def _test_c_histogram(s_tc, e_tc, _):
    assert compare_output(s_tc.histogram('height', 0, 200, 20, mincount=2),
                          e_tc.histogram('height', 0, 200, 20, mincount=2))

    h_s = s_tc.histogram('birthday',
                         '{n}-10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                         '{n}+10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                         '+1{d}'.format(d=s_tc.datastore.day, mincount=2))
    h_e = e_tc.histogram('birthday',
                         '{n}-10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                         '{n}+10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                         '+1{d}'.format(d=e_tc.datastore.day, mincount=2))
    assert compare_output(fix_date(h_s), fix_date(h_e))


def _test_c_facet(s_tc, e_tc, _):
    assert compare_output(s_tc.facet('tags'),
                          e_tc.facet('tags'))


def _test_c_stats(s_tc, e_tc, _):
    assert compare_output(s_tc.stats('height'),
                          e_tc.stats('height'))


def _test_c_groupsearch(s_tc, e_tc, as_obj):
    assert compare_output(s_tc.grouped_search('height', fl='flavour', as_obj=as_obj),
                          e_tc.grouped_search('height', fl='flavour', as_obj=as_obj))


def _test_c_fields(s_tc, e_tc, _):
    assert compare_output(s_tc.fields(), e_tc.fields())


TEST_CONSISTENCY_FUNC = [
    (_test_c_get, True, "get - object"),
    (_test_c_get, False, "get - dict"),
    (_test_c_mget, True, "multiget - object"),
    (_test_c_mget, False, "multiget - dict"),
    (_test_c_search, True, "search - object"),
    (_test_c_search, False, "search - dict"),
    (_test_c_streamsearch, True, "streamsearch - object"),
    (_test_c_streamsearch, False, "streamsearch - dict"),
    (_test_c_keys, None, "keys"),
    (_test_c_histogram, None, "histogram"),
    (_test_c_facet, None, "facet"),
    (_test_c_stats, None, "stats"),
    (_test_c_groupsearch, True, "groupsearch - object"),
    (_test_c_groupsearch, False, "groupsearch - dict"),
    (_test_c_fields, None, "fields"),
]


# noinspection PyShadowingNames
@pytest.mark.parametrize("function,as_obj", [(f[0], f[1]) for f in TEST_CONSISTENCY_FUNC],
                         ids=[f[2] for f in TEST_CONSISTENCY_FUNC])
def test_datastore_consistency(solr_connection, es_connection, function, as_obj):
    if solr_connection and es_connection:
        function(solr_connection, es_connection, as_obj)
