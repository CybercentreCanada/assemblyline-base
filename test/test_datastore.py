
import pytest
import warnings

from datemath import dm

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    test_map = {
        'test1': {'__expiry_ts__': dm('now-2d').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 400, 'test1': 'hello'},
        'test2': {'__expiry_ts__': dm('now-1d').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 100, 'test2': 'hello'},
        'test3': {'__expiry_ts__': dm('now').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 200, 'test3': 'hello'},
        'test4': {'__expiry_ts__': dm('now-2d').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 400, 'test4': 'hello'},
        'dict1': {'__expiry_ts__': dm('now-2d').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 400, 'classification': 'U', 'test1': 'hello'},
        'dict2': {'__expiry_ts__': dm('now').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 100, 'classification': 'U', 'test2': 'hello'},
        'dict3': {'__expiry_ts__': dm('now-3d').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 200, 'classification': 'C', 'test3': 'hello'},
        'dict4': {'__expiry_ts__': dm('now-1d').isoformat().replace('+00:00', 'Z'),
                  '__access_lvl__': 400, 'classification': 'TS', 'test4': 'hello'},
        'string': "A string!",
        'list': ['a', 'list', 'of', 'string', 100],
        'int': 69
    }


@pytest.fixture
def solr_connection():
    from assemblyline.datastore.stores.solr_store import SolrStore

    s = SolrStore(['127.0.0.1'])
    try:
        ret_val = s.ping()
        if ret_val:
            s.register("test_collection")

            # cleanup
            for k in test_map.keys():
                s.test_collection.delete(k)

            for k, v in test_map.items():
                s.test_collection.save(k, v)

            # Commit saved data
            s.test_collection.commit()

            return s.test_collection
    except ConnectionError:
        pass

    return pytest.skip("Connection to the SOLR server failed. This test cannot be performed...")


@pytest.fixture
def es_connection():
    from assemblyline.datastore.stores.es_store import ESStore

    e = ESStore(['127.0.0.1'])
    try:
        ret_val = e.ping()
        if ret_val:
            e.register("test_collection")
            # cleanup
            for k in test_map.keys():
                e.test_collection.delete(k)

            for k, v in test_map.items():
                e.test_collection.save(k, v)

            # Commit saved data
            e.test_collection.commit()

        return e.test_collection
    except ConnectionError:
        pass

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


@pytest.fixture
def riak_connection():
    from assemblyline.datastore.stores.riak_store import RiakStore

    r = RiakStore(['127.0.0.1'])
    try:
        ret_val = r.ping()
        if ret_val:
            r.register("test_collection")
            # cleanup
            for k in test_map.keys():
                r.test_collection.delete(k)

            for k, v in test_map.items():
                r.test_collection.save(k, v)

            # Commit saved data
            r.test_collection.commit()

        return r.test_collection
    except ConnectionError:
        pass

    return pytest.skip("Connection to the Redis server failed. This test cannot be performed...")


# noinspection PyShadowingNames
def test_solr(solr_connection):
    if solr_connection:
        s_tc = solr_connection

        assert test_map.get('test1') == s_tc.get('test1')
        assert test_map.get('test2') == s_tc.get('test2')
        assert test_map.get('test3') == s_tc.get('test3')
        assert test_map.get('test4') == s_tc.get('test4')
        assert test_map.get('string') == s_tc.get('string')
        assert test_map.get('list') == s_tc.get('list')
        assert test_map.get('int') == s_tc.get('int')

        raw = [test_map.get('test1'), test_map.get('int'), test_map.get('test2')]
        ds_raw = s_tc.multiget(['test1', 'int', 'test2'])
        for item in ds_raw:
            raw.remove(item)
        assert len(raw) == 0

        test_keys = list(test_map.keys())
        for k in s_tc.keys():
            test_keys.remove(k)
        assert len(test_keys) == 0


# noinspection PyShadowingNames
def test_es(es_connection):
    if es_connection:
        s_tc = es_connection

        assert test_map.get('test1') == s_tc.get('test1')
        assert test_map.get('test2') == s_tc.get('test2')
        assert test_map.get('test3') == s_tc.get('test3')
        assert test_map.get('test4') == s_tc.get('test4')
        assert test_map.get('string') == s_tc.get('string')
        assert test_map.get('list') == s_tc.get('list')
        assert test_map.get('int') == s_tc.get('int')

        raw = [test_map.get('test1'), test_map.get('int'), test_map.get('test2')]
        ds_raw = s_tc.multiget(['test1', 'int', 'test2'])
        for item in ds_raw:
            raw.remove(item)
        assert len(raw) == 0

        test_keys = list(test_map.keys())
        for k in s_tc.keys():
            test_keys.remove(k)
        assert len(test_keys) == 0


# noinspection PyShadowingNames
def test_riak(riak_connection):
    if riak_connection:
        s_tc = riak_connection

        assert test_map.get('test1') == s_tc.get('test1')
        assert test_map.get('test2') == s_tc.get('test2')
        assert test_map.get('test3') == s_tc.get('test3')
        assert test_map.get('test4') == s_tc.get('test4')
        assert test_map.get('string') == s_tc.get('string')
        assert test_map.get('list') == s_tc.get('list')
        assert test_map.get('int') == s_tc.get('int')

        raw = [test_map.get('test1'), test_map.get('int'), test_map.get('test2')]
        ds_raw = s_tc.multiget(['test1', 'int', 'test2'])
        for item in ds_raw:
            raw.remove(item)
        assert len(raw) == 0

        test_keys = list(test_map.keys())
        for k in s_tc.keys():
            test_keys.remove(k)
        assert len(test_keys) == 0


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

        try:
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

            assert compare_output(s_tc.grouped_search('__access_lvl__', fl='classification', offset=1, rows=2,
                                                      sort="__access_lvl__ desc"),
                                  e_tc.grouped_search('__access_lvl__', fl='classification', offset=1, rows=2,
                                                      sort="__access_lvl__ desc"),
                                  r_tc.grouped_search('__access_lvl__', fl='classification', offset=1, rows=2,
                                                      sort="__access_lvl__ desc"))

            # TODO: fields are not of the same type in-between datastores does that matter?
            #       will print output for now without failing the test
            compare_output(s_tc.fields(), e_tc.fields(), r_tc.fields())

        finally:
            for store in stores.values():
                store.wipe()
