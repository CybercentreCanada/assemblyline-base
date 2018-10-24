import json
import os

import requests
import riak
import threading
import time

from copy import copy

from assemblyline.datastore import collection_reconnect, log, DataStoreException
from assemblyline.datastore.stores.solr_store import SolrCollection, SolrStore


def utf8safe_encoder(obj):
    """
    This fixes riak unicode issues when strings in blob are already UTF-8.
    """
    return json.dumps(obj).encode('UTF-8')


class RiakCollection(SolrCollection):
    MULTIGET_MAX_RETRY = 5
    DEFAULT_SORT = "_yz_id asc"

    def __init__(self, datastore, name, model_class=None, solr_port=8093, riak_http_port=8098):
        self.riak_bucket = datastore.client.bucket(name)
        self.solr_port = solr_port
        self.riak_http_port = riak_http_port
        self.query_plan = None
        self.riak_api_base = "search/query"

        super().__init__(datastore, name, model_class=model_class, api_base="internal_solr")

    @collection_reconnect(log)
    def commit(self):
        for host in self.datastore.get_hosts():
            if ":" not in host:
                host += ":%s" % self.solr_port
            url = "http://{host}/{api_base}/{core}/update/?commit=true" \
                  "&softCommit=true&wt=json".format(host=host, api_base=self.api_base, core=self.name)

            res = requests.get(url)
            return res.ok

    # noinspection PyBroadException
    @staticmethod
    def get_data_from_riak_item(item):
        if item.encoded_data == 'None':
            return None
        try:
            return item.data
        except Exception:
            if item.bucket.name != 'blob':
                log.exception("[bucket:'%s', key:'%s'] Invalid data was inserted in the index, using alternate"
                              "decoding method to pull the data." % (item.bucket.name, item.key))
            return item.encoded_data

    @collection_reconnect(log)
    def multiget(self, key_list):
        temp_keys = copy(key_list)
        done = False
        retry = 0
        ret = []
        while not done:
            for bucket_item in self.riak_bucket.multiget(temp_keys):
                if not isinstance(bucket_item, tuple):
                    try:
                        item_data = RiakCollection.get_data_from_riak_item(bucket_item)
                    except DataStoreException:
                        continue
                    if item_data is not None:
                        if isinstance(item_data, dict):
                            item_data.pop(SolrCollection.EXTRA_SEARCH_FIELD, None)
                        ret.append(item_data)
                    temp_keys.remove(bucket_item.key)

            if len(temp_keys) == 0:
                done = True
            else:
                retry += 1

            if retry >= self.MULTIGET_MAX_RETRY:
                raise DataStoreException("%s is missing data for the following keys: %s" % (self.name.upper(),
                                                                                            temp_keys))
        return ret

    @collection_reconnect(log)
    def _get(self, key, retries):
        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:
            data = self.get_data_from_riak_item(self.riak_bucket.get(key))
            if data and isinstance(data, dict):
                data.pop(SolrCollection.EXTRA_SEARCH_FIELD, None)

            if data:
                return data

            if retries > 0:
                time.sleep(0.05)
                retries -= 1
            elif retries < 0:
                time.sleep(0.05)
            else:
                done = True

        return None

    def _save(self, key, data):
        item = self.riak_bucket.new(key=key, data=data, content_type='application/json')
        item.store()

    @collection_reconnect(log)
    def delete(self, key):
        self.riak_bucket.delete(key)

    def _cleanup_search_result(self, item):
        if isinstance(item, dict):
            item.pop('_source_', None)
            item.pop('_version_', None)
            item.pop('_yz_id', None)
            item.pop('_yz_rt', None)
            item.pop('_yz_rb', None)
            item.pop(self.EXTRA_SEARCH_FIELD, None)

        return item

    @collection_reconnect(log)
    def _search(self, args=None, port=None, api_base=None, search_api='select/'):
        if self.query_plan:
            temp_args = args + self.query_plan
            return super()._search(args=temp_args, port=self.solr_port, api_base=self.api_base, search_api=search_api)
        else:
            ret_val = super()._search(args=args, port=self.riak_http_port, api_base=self.riak_api_base, search_api="")

            qp = []
            for k, v in ret_val['responseHeader']['params'].items():
                if ":%s" % self.solr_port in k or ":8093" in k or k == "shards":
                    qp.append((k, v))
            self.query_plan = qp

            return ret_val

    @collection_reconnect(log)
    def histogram(self, field, start, end, gap, query="*", mincount=1, filters=(), access_control=None):
        ret_val = super().histogram(field, start, end, gap, query=query, mincount=mincount,
                                    filters=filters, access_control=access_control)

        # NOTE: mincount does not seem to be applied correctly in the solr instance provided by riak
        #       we will apply mincount here

        return {step: count for step, count in ret_val.items() if count >= mincount}

    @collection_reconnect(log)
    def keys(self, access_control=None):
        for item in self.stream_search("*", fl=self.datastore.ID, access_control=access_control):
            yield item[self.datastore.ID]

    @collection_reconnect(log)
    def _index_exists(self):
        try:
            self.datastore.client.get_search_index('name')
            return True
        except riak.RiakError as e:
            return False

    @collection_reconnect(log)
    def _ensure_collection(self):
        # TODO: get schema and nvals from model_class
        if not self._index_exists():
            log.warn("Collection {collection} does not exists. "
                     "Creating it now...".format(collection=self.name.upper()))
            schema_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../support/riak/schema.xml"))
            with open(schema_path) as sf:
                schema_raw = sf.read()
            nval = 1

            # TODO: Check if schema, index and bucket already exist before creating them blindly??!
            self.datastore.client.create_search_schema(schema=self.name, content=schema_raw)
            self.datastore.client.create_search_index(self.name, self.name, nval)
            props = {
                'dvv_enabled': False,
                'last_write_wins': True,
                'allow_mult': False,
                'n_val': nval,
                'search_index': self.name
            }
            self.datastore.client.set_bucket_props(bucket=self.riak_bucket, props=props)

    @collection_reconnect(log)
    def wipe(self):
        log.warning("Wipe operation started for collection: %s" % self.name.upper())

        for items in self.riak_bucket.stream_index("$bucket", ""):
            for item in items:
                log.warning("{bucket}: deleting key [{key}]".format(bucket=self.name, key=item))
                self.riak_bucket.delete(item)

        props = {
            'search_index': "_dont_index_"
        }
        self.datastore.client.set_bucket_props(bucket=self.riak_bucket, props=props)
        self.datastore.client.delete_search_index(self.name)


class RiakStore(SolrStore):
    """ Riak implementation of the ResultStore interface."""
    ID = "_yz_rk"
    DATE_FORMAT = {
        'NOW': 'NOW',
        'YEAR': 'YEAR',
        'MONTH': 'MONTH',
        'WEEK': 'WEEK',
        'DAY': 'DAY',
        'HOUR': 'HOUR',
        'MINUTE': 'MINUTE',
        'SECOND': 'SECOND',
        'MILLISECOND': 'MILLISECOND',
        'MICROSECOND': 'MICROSECOND',
        'NANOSECOND': 'NANOSECOND',
        'SEPARATOR': '',
    }

    # noinspection PyUnresolvedReferences
    def __init__(self, hosts=None, collection_class=RiakCollection, protocol_used='pbc',
                 solr_port=8093, riak_http_port=8098, riak_pb_port=8087):
        super().__init__(hosts, collection_class)
        self.CURRENT_QUERY_PLAN = {}

        self.riak_pb_port = riak_pb_port
        self.riak_http_port = riak_http_port
        self.solr_port = solr_port

        # Init Client
        self.riak_nodes = [{'host': n, 'pb_port': self.riak_pb_port, 'http_port': riak_http_port} for n in self._hosts]
        self.client = riak.RiakClient(protocol=protocol_used, nodes=self.riak_nodes)
        log.debug('riakclient opened...')

        # Set default encoders
        self.client.set_encoder('application/json', utf8safe_encoder)
        self.client.set_encoder('text/json', utf8safe_encoder)

        # Set default resolver
        self.client.resolver = riak.resolver.last_written_resolver

    def __str__(self):
        return '{0} - {1}:{2}'.format(
            self.__class__.__name__,
            self.hosts,
            self.riak_pb_port)

    def __getattr__(self, name):
        if name not in self._collections:
            model_class = self._models[name]
            self._collections[name] = self._collection_class(self, name, model_class=model_class,
                                                             solr_port=self.solr_port,
                                                             riak_http_port=self.riak_http_port)
        return self._collections[name]

    def ping(self):
        return self.client.ping()

    def close(self):
        super().close()

        if self.client:
            log.debug('riakclient closed...')
            self.client.close()
            self.client = None

        self._terminate_session(threading.get_ident())

    # noinspection PyBroadException
    def connection_reset(self):
        try:
            if not self.client.ping():
                self.client.close()
                self.client = None
                self.client = riak.RiakClient(protocol=self.protocol_used, nodes=self.riak_nodes)

        except Exception:
            pass

        for collection in self._collections.values():
            collection.query_plan = None

        self._terminate_session(threading.get_ident())


if __name__ == "__main__":
    from pprint import pprint

    s = RiakStore(['127.0.0.1'])
    s.register('user')
    s.user.delete('sgaron')
    s.user.delete('bob')
    s.user.delete('robert')
    s.user.delete('denis')

    s.user.save('sgaron', {'__expiry_ts__': '2018-10-10T16:26:42.961Z', 'uname': 'sgaron',
                           'is_admin': True, '__access_lvl__': 400})
    s.user.save('bob', {'__expiry_ts__': '2018-10-21T16:26:42.961Z', 'uname': 'bob',
                        'is_admin': False, '__access_lvl__': 100})
    s.user.save('denis', {'__expiry_ts__': '2018-10-19T16:26:42.961Z', 'uname': 'denis',
                          'is_admin': False, '__access_lvl__': 100})
    s.user.save('robert', {'__expiry_ts__': '2018-10-19T16:26:42.961Z', 'uname': 'robert',
                           'is_admin': False, '__access_lvl__': 200})

    s.user.commit()
    print('\n# get sgaron')
    pprint(s.user.get('sgaron'))
    print('\n# get bob')
    pprint(s.user.get('bob'))

    print('\n# multiget sgaron, robert, denis')
    pprint(s.user.multiget(['sgaron', 'robert', 'denis']))

    print('\n# search *:*')
    pprint(s.user.search("*:*"))

    print('\n# search __expiry_ts__ all fields')
    pprint(s.user.search('__expiry_ts__:"2018-10-18T16:26:42.961Z+1DAY"', fl="*"))

    print('\n# stream keys')
    for k in s.user.keys():
        print(k)

    print('\n# histogram number')
    pprint(s.user.histogram('__access_lvl__', 0, 1000, 100, mincount=2))

    print('\n# histogram date')
    pprint(s.user.histogram('__expiry_ts__', 'NOW-1MONTH/DAY', 'NOW+1DAY/DAY', '+1DAY'))

    print('\n# field analysis')
    pprint(s.user.field_analysis(s.ID))

    print('\n# grouped search')
    pprint(s.user.grouped_search(s.ID, rows=2, offset=1, sort='%s asc' % s.ID))
    pprint(s.user.grouped_search('__access_lvl__', rows=2, offset=1, sort='__access_lvl__ asc', fl=s.ID))

    print('\n# fields')
    pprint(s.user.fields())

    s.user.wipe()
    # print(s.user._search([('q', "*:*")]))
    # print(s.user._search([('q', "*:*"), ('fl', "*")]))
