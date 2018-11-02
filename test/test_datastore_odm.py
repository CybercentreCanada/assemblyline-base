
import pytest
import warnings
import random
import string

from datetime import datetime
from datemath import dm
from assemblyline.datastore import odm, log
import logging

log.setLevel(logging.INFO)


@odm.model(index=True, store=True)
class BModel(odm.Model):
    depth = odm.Integer()
    width = odm.Integer()


@odm.model(index=True, store=True)
class AModel(odm.Model):
    # id = odm.PrimaryKey()
    flavour = odm.Text()
    height = odm.Integer()
    birthday = odm.Date()
    tags = odm.List(odm.Keyword())
    size = odm.Compound(BModel, default={'depth': 100, 'width': 100})


with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    test_map = {
        'test1': AModel(dict(tags=['silly'], flavour='chocolate', height=100, birthday=dm('now-2d'))),
        'test2': AModel(dict(tags=['cats'], flavour='A little dry', height=180, birthday=dm('now-1d'))),
        'test3': AModel(dict(tags=['silly'], flavour='Red', height=140, birthday=dm('now'), size={'depth': 1, 'width': 1})),
        'test4': AModel(dict(tags=['cats'], flavour='Bugs ++', height=30, birthday='2018-10-30T17:48:48+00:00')),
        'dict1': AModel(dict(tags=['cats'], flavour='A--', height=300, birthday='2018-10-30T17:48:48Z')),
        'dict2': AModel(dict(tags=[], flavour='100%', height=90, birthday=datetime.utcnow())),
        'dict3': AModel(dict(tags=['10', 'cats'], flavour='', height=180, birthday=dm('now-3d'))),
        'dict4': AModel(dict(tags=['10', 'silly', 'cats'], flavour='blue', height=100, birthday=dm('now-1d'))),
    }


def setup_store(docstore, request):
    try:
        ret_val = docstore.ping()
        if ret_val:
            collection_name = ''.join(random.choices(string.ascii_lowercase, k=10))
            docstore.register(collection_name, AModel)
            docstore.register(collection_name, AModel)
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
    return None


@pytest.fixture
def solr_connection(request):
    from assemblyline.datastore.stores.solr_store import SolrStore

    collection = setup_store(SolrStore(['127.0.0.1']), request)
    if collection:
        return collection

    return pytest.skip("Connection to the SOLR server failed. This test cannot be performed...")


@pytest.fixture
def es_connection(request):
    from assemblyline.datastore.stores.es_store import ESStore

    collection = setup_store(ESStore(['127.0.0.1']), request)
    if collection:
        return collection

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


@pytest.fixture
def riak_connection(request):
    from assemblyline.datastore.stores.riak_store import RiakStore

    collection = setup_store(RiakStore(['127.0.0.1']), request)
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

        assert compare_output(s_tc.get('not-a-key'), e_tc.get('not-a-key'), r_tc.get('not-a-key'))
        assert compare_output(s_tc.get_if_exists('not-a-key'), e_tc.get_if_exists('not-a-key'), r_tc.get_if_exists('not-a-key'))

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
        assert compare_output(s_tc.search('*:*', offset=1, rows=1, filters="__access_lvl__:400",
                                          sort="%s asc" % s_tc.datastore.ID, fl='classification'),
                              e_tc.search('*:*', offset=1, rows=1, filters="__access_lvl__:400",
                                          sort="%s asc" % e_tc.datastore.ID, fl='classification'),
                              r_tc.search('*:*', offset=1, rows=1, filters="__access_lvl__:400",
                                          sort="%s asc" % r_tc.datastore.ID, fl='classification'))
        ss_s_list = list(s_tc.stream_search('classification:*', filters="__access_lvl__:400", fl='classification'))
        ss_e_list = list(e_tc.stream_search('classification:*', filters="__access_lvl__:400", fl='classification'))
        ss_r_list = list(r_tc.stream_search('classification:*', filters="__access_lvl__:400", fl='classification'))
        assert compare_output(ss_s_list, ss_e_list, ss_r_list)

        assert compare_output(sorted(list(s_tc.keys())), sorted(list(e_tc.keys())), sorted(list(r_tc.keys())))
        assert compare_output(s_tc.histogram('__access_lvl__', 0, 1000, 100, mincount=2),
                              e_tc.histogram('__access_lvl__', 0, 1000, 100, mincount=2),
                              r_tc.histogram('__access_lvl__', 0, 1000, 100, mincount=2))

        h_s = s_tc.histogram('__expiry_ts__',
                             '{n}-10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=s_tc.datastore.now, d=s_tc.datastore.day),
                             '+1{d}'.format(d=s_tc.datastore.day, mincount=2))
        h_e = e_tc.histogram('__expiry_ts__',
                             '{n}-10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=e_tc.datastore.now, d=e_tc.datastore.day),
                             '+1{d}'.format(d=e_tc.datastore.day, mincount=2))
        h_r = r_tc.histogram('__expiry_ts__',
                             '{n}-10{d}/{d}'.format(n=r_tc.datastore.now, d=r_tc.datastore.day),
                             '{n}+10{d}/{d}'.format(n=r_tc.datastore.now, d=r_tc.datastore.day),
                             '+1{d}'.format(d=r_tc.datastore.day, mincount=2))
        assert compare_output(fix_date(h_s), fix_date(h_e), fix_date(h_r))
        assert compare_output(s_tc.field_analysis('classification'),
                              e_tc.field_analysis('classification'),
                              r_tc.field_analysis('classification'))

        assert compare_output(s_tc.grouped_search('__access_lvl__', fl='classification'),
                              e_tc.grouped_search('__access_lvl__', fl='classification'),
                              r_tc.grouped_search('__access_lvl__', fl='classification'))

        # TODO: fields are not of the same type in-between datastores does that matter?
        #       will print output for now without failing the test
        compare_output(s_tc.fields(), e_tc.fields(), r_tc.fields())
