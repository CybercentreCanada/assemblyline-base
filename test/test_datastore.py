import pytest


@pytest.fixture
def solr_connection():
    from assemblyline.datastore.stores.solr_store import SolrStore

    s = SolrStore(['127.0.0.1'])
    try:
        ret_val = s.ping()
        if ret_val:
            return s
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
            return e
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
            return r
    except ConnectionError:
        pass

    return pytest.skip("Connection to the Redis server failed. This test cannot be performed...")


# noinspection PyShadowingNames
def test_solr(solr_connection):
    if solr_connection:
        s = solr_connection

        s.register('test_collection')

        try:
            # cleanup
            s.test_collection.delete('test1')
            s.test_collection.delete('test2')
            s.test_collection.delete('test3')
            s.test_collection.delete('test4')
            s.test_collection.delete('string')
            s.test_collection.delete('list')
            s.test_collection.delete('int')

            test1_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400, 'test1': 'hello'}
            test2_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100, 'test2': 'hello'}
            test3_data = {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200, 'test3': 'hello'}
            test4_data = {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400, 'test4': 'hello'}
            test_string = "A string!"
            test_list = ['a', 'list', 'of', 'string', 1]
            test_int = 1

            test_keys = ['test1', 'test2', 'test3', 'test4', 'string', 'list', 'int']

            # Save data
            s.test_collection.save('test1', test1_data)
            s.test_collection.save('test2', test2_data)
            s.test_collection.save('test3', test3_data)
            s.test_collection.save('test4', test4_data)
            s.test_collection.save('string', test_string)
            s.test_collection.save('list', test_list)
            s.test_collection.save('int', test_int)

            # Commit saved data
            s.test_collection.commit()

            assert test1_data == s.test_collection.get('test1')
            assert test2_data == s.test_collection.get('test2')
            assert test3_data == s.test_collection.get('test3')
            assert test4_data == s.test_collection.get('test4')
            assert test_string == s.test_collection.get('string')
            assert test_list == s.test_collection.get('list')
            assert test_int == s.test_collection.get('int')

            raw = [test1_data, test_int, test2_data]
            ds_raw = s.test_collection.multiget(['test1', 'int', 'test2'])
            for item in ds_raw:
                raw.remove(item)
            assert len(raw) == 0

            for k in s.test_collection.keys():
                test_keys.remove(k)
            assert len(test_keys) == 0

        finally:
            s.test_collection.wipe()


# noinspection PyShadowingNames
def test_es(es_connection):
    if es_connection:
        s = es_connection

        s.register('test_collection')

        try:
            # cleanup
            s.test_collection.delete('test1')
            s.test_collection.delete('test2')
            s.test_collection.delete('test3')
            s.test_collection.delete('test4')
            s.test_collection.delete('string')
            s.test_collection.delete('list')
            s.test_collection.delete('int')

            test1_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400, 'test1': 'hello'}
            test2_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100, 'test2': 'hello'}
            test3_data = {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200, 'test3': 'hello'}
            test4_data = {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400, 'test4': 'hello'}
            test_string = "A string!"
            test_list = ['a', 'list', 'of', 'string', 1]
            test_int = 1

            test_keys = ['test1', 'test2', 'test3', 'test4', 'string', 'list', 'int']

            # Save data
            s.test_collection.save('test1', test1_data)
            s.test_collection.save('test2', test2_data)
            s.test_collection.save('test3', test3_data)
            s.test_collection.save('test4', test4_data)
            s.test_collection.save('string', test_string)
            s.test_collection.save('list', test_list)
            s.test_collection.save('int', test_int)

            # Commit saved data
            s.test_collection.commit()

            assert test1_data == s.test_collection.get('test1')
            assert test2_data == s.test_collection.get('test2')
            assert test3_data == s.test_collection.get('test3')
            assert test4_data == s.test_collection.get('test4')
            assert test_string == s.test_collection.get('string')
            assert test_list == s.test_collection.get('list')
            assert test_int == s.test_collection.get('int')

            raw = [test1_data, test_int, test2_data]
            ds_raw = s.test_collection.multiget(['test1', 'int', 'test2'])
            for item in ds_raw:
                raw.remove(item)
            assert len(raw) == 0

            for k in s.test_collection.keys():
                test_keys.remove(k)
            assert len(test_keys) == 0

        finally:
            s.test_collection.wipe()


# noinspection PyShadowingNames
def test_riak(riak_connection):
    if riak_connection:
        s = riak_connection

        s.register('test_collection')

        try:
            # cleanup
            s.test_collection.delete('test1')
            s.test_collection.delete('test2')
            s.test_collection.delete('test3')
            s.test_collection.delete('test4')
            s.test_collection.delete('string')
            s.test_collection.delete('list')
            s.test_collection.delete('int')

            test1_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400, 'test1': 'hello'}
            test2_data = {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100, 'test2': 'hello'}
            test3_data = {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200, 'test3': 'hello'}
            test4_data = {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400, 'test4': 'hello'}
            test_string = "A string!"
            test_list = ['a', 'list', 'of', 'string', 1]
            test_int = 1

            test_keys = ['test1', 'test2', 'test3', 'test4', 'string', 'list', 'int']

            # Save data
            s.test_collection.save('test1', test1_data)
            s.test_collection.save('test2', test2_data)
            s.test_collection.save('test3', test3_data)
            s.test_collection.save('test4', test4_data)
            s.test_collection.save('string', test_string)
            s.test_collection.save('list', test_list)
            s.test_collection.save('int', test_int)

            # Commit saved data
            s.test_collection.commit()

            assert test1_data == s.test_collection.get('test1')
            assert test2_data == s.test_collection.get('test2')
            assert test3_data == s.test_collection.get('test3')
            assert test4_data == s.test_collection.get('test4')
            assert test_string == s.test_collection.get('string')
            assert test_list == s.test_collection.get('list')
            assert test_int == s.test_collection.get('int')

            raw = [test1_data, test_int, test2_data]
            ds_raw = s.test_collection.multiget(['test1', 'int', 'test2'])
            for item in ds_raw:
                raw.remove(item)
            assert len(raw) == 0

            for k in s.test_collection.keys():
                test_keys.remove(k)
            assert len(test_keys) == 0

        finally:
            s.test_collection.wipe()


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

        stores = {
            'solr': solr_connection,
            'elastic': es_connection,
            'riak': riak_connection
        }

        for store in stores.values():
            store.register('test_consistency')

        try:
            raw_data = [{'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 400, 'test1': 'hello'},
                {'__expiry_ts__': '2018-10-10T16:26:42.961Z', '__access_lvl__': 100, 'test2': 'hello'},
                {'__expiry_ts__': '2018-10-11T16:26:42.961Z', '__access_lvl__': 200, 'test3': 'hello'},
                {'__expiry_ts__': '2018-10-12T16:26:42.961Z', '__access_lvl__': 400, 'test4': 'hello'}
            ]

            for store in stores.values():
                count = 0
                for data in raw_data:
                    count += 1
                    store.test_consistency.save('dict%s' % count, data)

            for store in stores.values():
                store.test_consistency.save('int', 1)

            for store in stores.values():
                store.test_consistency.save('string', 'a')

            for store in stores.values():
                store.test_consistency.save('list', [1, 2, 'a'])

            for store in stores.values():
                store.test_consistency.commit()

            s_tc = stores['solr'].test_consistency
            e_tc = stores['elastic'].test_consistency
            r_tc = stores['riak'].test_consistency

            assert compare_output(s_tc.get('list'), e_tc.get('list'), r_tc.get('list'))
            assert compare_output(s_tc.get('string'), e_tc.get('string'), r_tc.get('string'))
            assert compare_output(s_tc.get('int'), e_tc.get('int'), r_tc.get('int'))
            for x in range(5):
                key = 'dict%s' % x
                assert compare_output(s_tc.get(key), e_tc.get(key), r_tc.get(key))

        finally:
            for store in stores.values():
                store.test_consistency.wipe()




