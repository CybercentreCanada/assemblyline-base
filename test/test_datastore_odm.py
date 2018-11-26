import logging
import pytest
import random
import string
import warnings

from datetime import datetime
from datemath import dm
from retrying import retry

from assemblyline.datastore import odm, log

log.setLevel(logging.INFO)


@odm.model(index=True, store=True)
class ThingsModel(odm.Model):
    count = odm.Integer()
    thing = odm.Text()


@odm.model(index=True, store=True)
class MeasurementModel(odm.Model):
    depth = odm.Integer()
    width = odm.Integer()


@odm.model(index=True, store=True)
class BaseTestModel(odm.Model):
    flavour = odm.Text(copyto='features', default="EMPTY")
    height = odm.Integer()
    birthday = odm.Date()
    tags = odm.List(odm.Keyword(), default=[], copyto='features')
    size = odm.Compound(MeasurementModel, default={'depth': 100, 'width': 100})
    features = odm.List(odm.Text(), default=[])
    metadata = odm.Mapping(odm.Text(), default={})
    things = odm.List(odm.Compound(ThingsModel), default=[])


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    test_map = {
        'test1': BaseTestModel(dict(tags=['silly'], flavour='chocolate', height=100, birthday=dm('now-2d'),
                                    metadata={'url': 'google.com'}, things=[{'count': 1, 'thing': 'hat'}])),
        'test2': BaseTestModel(dict(tags=['cats'], flavour='A little dry', height=180, birthday=dm('now-1d'),
                                    metadata={'url': 'google.ca'})),
        'test3': BaseTestModel(dict(tags=['silly'], flavour='Red', height=140, birthday=dm('now'),
                                    size={'depth': 1, 'width': 1}, things=[{'count': 1, 'thing': 'hat'},
                                                                           {'count': 10, 'thing': 'shoe'}])),
        'test4': BaseTestModel(dict(tags=['cats'], flavour='Bugs ++', height=30, birthday='2018-10-30T17:48:48+00:00')),
        'dict1': BaseTestModel(dict(tags=['cats'], flavour='A--', height=300, birthday='2018-10-30T17:48:48Z')),
        'dict2': BaseTestModel(dict(tags=[], flavour='100%', height=90, birthday=datetime.utcnow(),
                                    metadata={'origin': 'space'})),
        'dict3': BaseTestModel(dict(tags=['10', 'cats'], flavour='', height=180, birthday=dm('now-3d'))),
        'dict4': BaseTestModel(dict(tags=['10', 'silly', 'cats'], flavour='blue', height=100, birthday=dm('now-1d'))),
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


def collection_test(collection):
    col = collection

    assert test_map.get('test1') == col.get('test1')
    assert test_map.get('test2') == col.get('test2')
    assert test_map.get('test3') == col.get('test3')
    assert test_map.get('test4') == col.get('test4')

    assert col.get('string') is None
    assert col.get('list') is None
    assert col.get('int') is None

    raw = [test_map.get('test1'), test_map.get('dict1'), test_map.get('test2')]
    ds_raw = col.multiget(['test1', 'dict1', 'test2'])
    for item in ds_raw:
        raw.remove(item)
    assert len(raw) == 0

    test_keys = list(test_map.keys())
    for k in col.keys():
        test_keys.remove(k)
    assert len(test_keys) == 0

    with pytest.raises(KeyError) as error_info:
        print(col.multiget(['not-a-key-1', 'not-a-key-2']))
    assert 'not-a-key' in str(error_info.value)

    col.search('*:*', sort="%s asc" % col.datastore.ID)

    # reading list fields on a search
    assert len(col.search(f'{col.datastore.ID}: dict3')['items'][0].tags) == 2
    assert len(col.search(f'{col.datastore.ID}: dict4')['items'][0].tags) == 3

    # reading single fields on a search
    assert col.search(f'{col.datastore.ID}: test1')['items'][0].flavour == 'chocolate'

    # Make sure sorting on the ID key works right
    forward = col.search('*', sort=f'{col.datastore.ID} asc')
    reverse = col.search('*', sort=f'{col.datastore.ID} desc')
    assert forward['items'] == list(reversed(reverse['items']))

    # Search on a copyto field
    assert col.search('features: chocolate')['total'] == 1

    # Make sure we are getting only the expected fields with a field list
    with pytest.raises(odm.KeyMaskException):
        result = col.search('features: chocolate', fl='features')
        assert result['total'] == 1
        _ = result['items'][0].flavour

    # Check that the metadata is searchable
    assert col.search('metadata.url:*google*')['total'] == 2


# noinspection PyShadowingNames
def test_solr(solr_connection):
    collection_test(solr_connection)


# noinspection PyShadowingNames
def test_es(es_connection):
    collection_test(es_connection)


# noinspection PyShadowingNames
def test_riak(riak_connection):
    collection_test(riak_connection)


# noinspection PyShadowingNames
def test_datastore_consistency(riak_connection, solr_connection, es_connection):
    if riak_connection and solr_connection and es_connection:

        def fix_date(data):
            # making date precision all the same throughout the datastores so we can compared them
            return {k.replace(".000", ""): v for k, v in data.items()}

        def fix_ids(data):
            # We're remapping all id fields to a default value so we can compare outputs
            data['items'] = [item.id for item in data['items']]
            return data

        def compare_output(solr, elastic, riak):
            errors = []

            try:
                if solr != riak:
                    errors.append("solr != riak")
            except odm.KeyMaskException:
                errors.append("solr != riak")

            try:
                if solr != elastic:
                    errors.append("solr != elastic")
            except odm.KeyMaskException:
                errors.append("solr != elastic")

            try:
                if elastic != riak:
                    errors.append("elastic != riak")
            except odm.KeyMaskException:
                errors.append("elastic != riak")

            if errors:
                print("\n\nNot all outputs are equal: {non_equal}\n\n"
                      "solr = {solr}\nelastic = {elastic}\nriak = {riak}\n\n".format(non_equal=", ".join(errors),
                                                                                     solr=solr,
                                                                                     elastic=elastic,
                                                                                     riak=riak))
                return False

            return True

        s_tc = solr_connection
        e_tc = es_connection
        r_tc = riak_connection
        stores = [s_tc, e_tc, r_tc]

        assert compare_output(s_tc.get('not-a-key'), e_tc.get('not-a-key'), r_tc.get('not-a-key'))
        assert compare_output(*(tc.get_if_exists('not-a-key') for tc in stores))

        assert compare_output(s_tc.get('test1'), e_tc.get('test1'), r_tc.get('test1'))
        assert compare_output(s_tc.require('test1'), e_tc.require('test1'), r_tc.require('test1'))
        assert compare_output(s_tc.get_if_exists('test1'), e_tc.get_if_exists('test1'), r_tc.get_if_exists('test1'))

        for x in range(5):
            key = 'dict%s' % x
            assert compare_output(s_tc.get(key), e_tc.get(key), r_tc.get(key))

        assert compare_output(s_tc.multiget(['test1', 'test1']),
                              e_tc.multiget(['test1', 'test1']),
                              r_tc.multiget(['test1', 'test1']))
        assert compare_output(fix_ids(s_tc.search('*:*', sort="%s asc" % s_tc.datastore.ID)),
                              fix_ids(e_tc.search('*:*', sort="%s asc" % e_tc.datastore.ID)),
                              fix_ids(r_tc.search('*:*', sort="%s asc" % r_tc.datastore.ID)))
        assert compare_output(s_tc.search('*:*', offset=1, rows=1, filters="height:100",
                                          sort="%s asc" % s_tc.datastore.ID, fl='flavour'),
                              e_tc.search('*:*', offset=1, rows=1, filters="height:100",
                                          sort="%s asc" % e_tc.datastore.ID, fl='flavour'),
                              r_tc.search('*:*', offset=1, rows=1, filters="height:100",
                                          sort="%s asc" % r_tc.datastore.ID, fl='flavour'))
        ss_s_list = list(s_tc.stream_search('flavour:*', filters="height:[30 TO 400]", fl='flavour'))
        ss_e_list = list(e_tc.stream_search('flavour:*', filters="height:[30 TO 400]", fl='flavour'))
        ss_r_list = list(r_tc.stream_search('flavour:*', filters="height:[30 TO 400]", fl='flavour'))
        assert compare_output(ss_s_list, ss_e_list, ss_r_list)

        assert compare_output(sorted(list(s_tc.keys())), sorted(list(e_tc.keys())), sorted(list(r_tc.keys())))
        assert compare_output(s_tc.histogram('height', 0, 200, 20, mincount=2),
                              e_tc.histogram('height', 0, 200, 20, mincount=2),
                              r_tc.histogram('height', 0, 200, 20, mincount=2))

        h_s = s_tc.histogram('birthday',
                             '{n}-10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                             '+1{d}'.format(d=s_tc.datastore.day, mincount=2))
        h_e = e_tc.histogram('birthday',
                             '{n}-10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                             '+1{d}'.format(d=e_tc.datastore.day, mincount=2))
        h_r = r_tc.histogram('birthday',
                             '{n}-10{d}/{d}'.format(n=r_tc.datastore.now, d=r_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=r_tc.datastore.now, d=r_tc.datastore.day),
                             '+1{d}'.format(d=r_tc.datastore.day, mincount=2))
        assert compare_output(fix_date(h_s), fix_date(h_e), fix_date(h_r))
        assert compare_output(s_tc.field_analysis('tags'),
                              e_tc.field_analysis('tags'),
                              r_tc.field_analysis('tags'))

        assert compare_output(s_tc.grouped_search('height', fl='flavour'),
                              e_tc.grouped_search('height', fl='flavour'),
                              r_tc.grouped_search('height', fl='flavour'))
        #
        # # TODO: fields are not of the same type in-between datastores does that matter?
        # #       will print output for now without failing the test
        # compare_output(s_tc.fields(), e_tc.fields(), r_tc.fields())
