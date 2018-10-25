import pytest


@pytest.fixture
def solr_connection():
    from assemblyline.datastore.stores.solr_store import SolrStore

    s = SolrStore(['127.0.0.1'])
    try:
        ret_val = s.ping()
        if ret_val:
            s.register("test_collection")
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
            return r.test_collection
    except ConnectionError:
        pass

    return pytest.skip("Connection to the Redis server failed. This test cannot be performed...")


# noinspection PyShadowingNames
def test_solr(solr_connection):
    if solr_connection:
        s_tc = solr_connection

        # cleanup
        s_tc.delete('test1')
        s_tc.delete('test2')
        s_tc.delete('test3')
        s_tc.delete('test4')
        s_tc.delete('string')
        s_tc.delete('list')
        s_tc.delete('int')

        test1_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400, 'test1': 'hello'}
        test2_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100, 'test2': 'hello'}
        test3_data = {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200, 'test3': 'hello'}
        test4_data = {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400, 'test4': 'hello'}
        test_string = "A string!"
        test_list = ['a', 'list', 'of', 'string', 1]
        test_int = 1

        test_keys = ['test1', 'test2', 'test3', 'test4', 'string', 'list', 'int']

        # Save data
        s_tc.save('test1', test1_data)
        s_tc.save('test2', test2_data)
        s_tc.save('test3', test3_data)
        s_tc.save('test4', test4_data)
        s_tc.save('string', test_string)
        s_tc.save('list', test_list)
        s_tc.save('int', test_int)

        # Commit saved data
        s_tc.commit()

        assert test1_data == s_tc.get('test1')
        assert test2_data == s_tc.get('test2')
        assert test3_data == s_tc.get('test3')
        assert test4_data == s_tc.get('test4')
        assert test_string == s_tc.get('string')
        assert test_list == s_tc.get('list')
        assert test_int == s_tc.get('int')

        raw = [test1_data, test_int, test2_data]
        ds_raw = s_tc.multiget(['test1', 'int', 'test2'])
        for item in ds_raw:
            raw.remove(item)
        assert len(raw) == 0

        for k in s_tc.keys():
            test_keys.remove(k)
        assert len(test_keys) == 0


# noinspection PyShadowingNames
def test_es(es_connection):
    if es_connection:
        s_tc = es_connection

        # cleanup
        s_tc.delete('test1')
        s_tc.delete('test2')
        s_tc.delete('test3')
        s_tc.delete('test4')
        s_tc.delete('string')
        s_tc.delete('list')
        s_tc.delete('int')

        test1_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400, 'test1': 'hello'}
        test2_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100, 'test2': 'hello'}
        test3_data = {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200, 'test3': 'hello'}
        test4_data = {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400, 'test4': 'hello'}
        test_string = "A string!"
        test_list = ['a', 'list', 'of', 'string', 1]
        test_int = 1

        test_keys = ['test1', 'test2', 'test3', 'test4', 'string', 'list', 'int']

        # Save data
        s_tc.save('test1', test1_data)
        s_tc.save('test2', test2_data)
        s_tc.save('test3', test3_data)
        s_tc.save('test4', test4_data)
        s_tc.save('string', test_string)
        s_tc.save('list', test_list)
        s_tc.save('int', test_int)

        # Commit saved data
        s_tc.commit()

        assert test1_data == s_tc.get('test1')
        assert test2_data == s_tc.get('test2')
        assert test3_data == s_tc.get('test3')
        assert test4_data == s_tc.get('test4')
        assert test_string == s_tc.get('string')
        assert test_list == s_tc.get('list')
        assert test_int == s_tc.get('int')

        raw = [test1_data, test_int, test2_data]
        ds_raw = s_tc.multiget(['test1', 'int', 'test2'])
        for item in ds_raw:
            raw.remove(item)
        assert len(raw) == 0

        for k in s_tc.keys():
            test_keys.remove(k)
        assert len(test_keys) == 0


# noinspection PyShadowingNames
def test_riak(riak_connection):
    if riak_connection:
        s_tc = riak_connection

        # cleanup
        s_tc.delete('test1')
        s_tc.delete('test2')
        s_tc.delete('test3')
        s_tc.delete('test4')
        s_tc.delete('string')
        s_tc.delete('list')
        s_tc.delete('int')

        test1_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400, 'test1': 'hello'}
        test2_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100, 'test2': 'hello'}
        test3_data = {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200, 'test3': 'hello'}
        test4_data = {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400, 'test4': 'hello'}
        test_string = "A string!"
        test_list = ['a', 'list', 'of', 'string', 1]
        test_int = 1

        test_keys = ['test1', 'test2', 'test3', 'test4', 'string', 'list', 'int']

        # Save data
        s_tc.save('test1', test1_data)
        s_tc.save('test2', test2_data)
        s_tc.save('test3', test3_data)
        s_tc.save('test4', test4_data)
        s_tc.save('string', test_string)
        s_tc.save('list', test_list)
        s_tc.save('int', test_int)

        # Commit saved data
        s_tc.commit()

        assert test1_data == s_tc.get('test1')
        assert test2_data == s_tc.get('test2')
        assert test3_data == s_tc.get('test3')
        assert test4_data == s_tc.get('test4')
        assert test_string == s_tc.get('string')
        assert test_list == s_tc.get('list')
        assert test_int == s_tc.get('int')

        raw = [test1_data, test_int, test2_data]
        ds_raw = s_tc.multiget(['test1', 'int', 'test2'])
        for item in ds_raw:
            raw.remove(item)
        assert len(raw) == 0

        for k in s_tc.keys():
            test_keys.remove(k)
        assert len(test_keys) == 0


# noinspection PyShadowingNames
def test_datastore_consistency(riak_connection, solr_connection, es_connection):
    if riak_connection and solr_connection and es_connection:

        def compare_output(solr, elastic, riak):
            errors = []

            if solr != riak:
                errors.append("solr != riak")

            if solr != elastic:
                errors.append("solr != elastic")

            if elastic != riak:
                errors.append("elastic != riak")

            if errors:
                raise ValueError("Not all outputs are equal: {non_equal} "
                                 "[{solr}, {elastic}, {riak}]".format(non_equal=", ".join(errors),
                                                                      solr=solr,
                                                                      elastic=elastic,
                                                                      riak=riak))
            return True

        stores = {}
        s_tc = stores['solr'] = solr_connection
        e_tc = stores['elastic'] = es_connection
        r_tc = stores['riak'] = riak_connection

        try:
            raw_data = [
                {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400,
                 'classification': 'U', 'test1': 'hello'},
                {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100,
                 'classification': 'U', 'test2': 'hello'},
                {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200,
                 'classification': 'C', 'test3': 'hello'},
                {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400,
                 'classification': 'TS', 'test4': 'hello'}
            ]

            for store in stores.values():
                count = 0
                for data in raw_data:
                    count += 1
                    store.save('dict%s' % count, data)

            for store in stores.values():
                store.save('int', 1)

            for store in stores.values():
                store.save('string', 'a')

            for store in stores.values():
                store.save('list', [1, 2, 'a'])

            for store in stores.values():
                store.commit()

            assert compare_output(s_tc.get('list'), e_tc.get('list'), r_tc.get('list'))
            assert compare_output(s_tc.require('string'), e_tc.require('string'), r_tc.require('string'))
            assert compare_output(s_tc.get_if_exists('int'), e_tc.get_if_exists('int'), r_tc.get_if_exists('int'))
            for x in range(5):
                key = 'dict%s' % x
                assert compare_output(s_tc.get(key), e_tc.get(key), r_tc.get(key))
            assert compare_output(s_tc.multiget(['int', 'int']),
                                  e_tc.multiget(['int', 'int']),
                                  r_tc.multiget(['int', 'int']))
            assert compare_output(s_tc.search('*:*', offset=1, rows=1, filters="__access_lvl__:400",
                                              sort="%s asc" % s_tc.datastore.ID, fl='classification'),
                                  e_tc.search('*:*', offset=1, rows=1, filters="__access_lvl__:400",
                                              sort="%s asc" % e_tc.datastore.ID, fl='classification'),
                                  r_tc.search('*:*', offset=1, rows=1, filters="__access_lvl__:400",
                                              sort="%s asc" %r_tc.datastore.ID, fl='classification'))
            ss_s_list = list(s_tc.stream_search('classification:*', filters="__access_lvl__:400", fl='classification'))
            ss_e_list = list(e_tc.stream_search('classification:*', filters="__access_lvl__:400", fl='classification'))
            ss_r_list = list(r_tc.stream_search('classification:*', filters="__access_lvl__:400", fl='classification'))
            assert compare_output(ss_s_list, ss_e_list, ss_r_list)

            assert compare_output(sorted(list(s_tc.keys())), sorted(list(e_tc.keys())), sorted(list(r_tc.keys())))
            assert compare_output(s_tc.histogram('__access_lvl__', 0, 1000, 100, mincount=2),
                                  e_tc.histogram('__access_lvl__', 0, 1000, 100, mincount=2),
                                  r_tc.histogram('__access_lvl__', 0, 1000, 100, mincount=2))

        finally:
            for store in stores.values():
                store.wipe()




