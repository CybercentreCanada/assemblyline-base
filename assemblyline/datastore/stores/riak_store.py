import json
import os

import requests
import riak
import threading
import time

from copy import copy

from assemblyline.datastore import log, DataStoreException
from assemblyline.datastore.stores.solr_store import SolrCollection, SolrStore
from assemblyline.datastore.support.riak.build import build_mapping


def utf8safe_encoder(obj):
    """
    This fixes riak unicode issues when strings in blob are already UTF-8.
    """
    return json.dumps(obj).encode('UTF-8')


class RiakCollection(SolrCollection):
    MULTIGET_MAX_RETRY = 5
    DEFAULT_SORT = "_yz_id asc"
    DEFAULT_CATCH_ALL_FIELDS = """
    <dynamicField name="*_i"  type="int"    indexed="true"  stored="true"  multiValued="false"/>
    <dynamicField name="*_is" type="int"    indexed="true"  stored="true"  multiValued="true"/>
    <dynamicField name="*_l"  type="long"   indexed="true"  stored="true"  multiValued="false"/>
    <dynamicField name="*_ls" type="long"   indexed="true"  stored="true"  multiValued="true"/>
    <dynamicField name="*_d"  type="double" indexed="true"  stored="true"  multiValued="false"/>
    <dynamicField name="*_ds" type="double" indexed="true"  stored="true"  multiValued="true"/>
    <dynamicField name="*_f"  type="float"  indexed="true"  stored="true"  multiValued="false"/>
    <dynamicField name="*_fs" type="float"  indexed="true"  stored="true"  multiValued="true"/>

    <dynamicField name="*_s"  type="string"  indexed="true"  stored="true" multiValued="false"/>
    <dynamicField name="*_ss" type="string"  indexed="true"  stored="true" multiValued="true"/>

    <dynamicField name="*_t"  type="text" indexed="true"  stored="true" multiValued="false"/>
    <dynamicField name="*_ts"  type="text" indexed="true"  stored="true" multiValued="true"/>

    <dynamicField name="*_b"  type="boolean" indexed="true" stored="true" multiValued="false"/>
    <dynamicField name="*_bs" type="boolean" indexed="true" stored="true"  multiValued="true"/>
    <dynamicField name="*_dt"  type="date"    indexed="true"  stored="true" multiValued="false"/>
    <dynamicField name="*_dts" type="date"    indexed="true"  stored="true" multiValued="true"/>
     """
    RIAK_RECONNECT_MSGS = [
        "insufficient_vnodes",
        "Unknown message code: ",
        "all_nodes_down",
        "Socket returned short packet",
        "Not enough nodes are up to service this request.",
        "connected host has failed to respond",
        "target machine actively refused it",
        "timeout",
        "Connection refused",
        "Truncated message",
        "Truncated string",
        "Unexpected end-group tag",
        "unknown msg code",
        "key must be a string, instead got None",
        "Tag had invalid wire type",
        "returned zero bytes unexpectedly",
        "unexpected message code:",
        "Client is closed.",
        "established connection was aborted",
        "existing connection was forcibly closed"
    ]
    RIAK_ABORT_MSGS = [
        "too_large"
    ]

    def __init__(self, datastore, name, model_class=None, solr_port=8093, riak_http_port=8098):
        self.riak_bucket = datastore.client.bucket(name)
        self.solr_port = solr_port
        self.riak_http_port = riak_http_port
        self.query_plan = None
        self.riak_api_base = "search/query"

        super().__init__(datastore, name, model_class=model_class, api_base="internal_solr")

    def with_retries(self, func, *args, **kwargs):
        retries = 0
        while True:
            try:
                return func(*args, **kwargs)
            except OverflowError:
                self.datastore.connection_reset()
                retries += 1
            except riak.RiakError as e:
                error = str(e)
                if any(msg in error for msg in self.RIAK_ABORT_MSGS):
                    raise
                self.datastore.connection_reset()
                retries += 1
            except Exception as e:
                error = str(e)
                re_raise = True
                if any(msg in error for msg in self.RIAK_RECONNECT_MSGS):
                    if retries < self.MAX_RETRY_BACKOFF:
                        time.sleep(retries)
                    else:
                        time.sleep(self.MAX_RETRY_BACKOFF)
                    if log and retries % 10 == 0:
                        log.debug("Reconnecting to riak: %s", error)
                    self.datastore.connection_reset()
                    re_raise = False

                if re_raise:
                    raise
                else:
                    retries += 1

    def commit(self):
        for host in self.datastore.get_hosts():
            if ":" not in host:
                host += ":%s" % self.solr_port
            url = "http://{host}/{api_base}/{core}/update/?commit=true" \
                  "&softCommit=true&wt=json".format(host=host, api_base=self.api_base, core=self.name)

            res = self.with_retries(requests.get, url)
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

    def multiget(self, key_list):
        temp_keys = copy(key_list)
        done = False
        retry = 0
        ret = []
        while not done:
            for bucket_item in self.with_retries(self.riak_bucket.multiget, temp_keys):
                if not isinstance(bucket_item, tuple):
                    try:
                        item_data = RiakCollection.get_data_from_riak_item(bucket_item)
                    except DataStoreException:
                        continue

                    if item_data is not None:
                        if isinstance(item_data, dict):
                            item_data.pop(SolrCollection.EXTRA_SEARCH_FIELD, None)
                        ret.append(self.normalize(item_data))
                        temp_keys.remove(bucket_item.key)

            if len(temp_keys) == 0:
                done = True
            else:
                retry += 1

            if retry >= self.MULTIGET_MAX_RETRY:
                raise KeyError(str(temp_keys))
        return ret

    def _get(self, key, retries):
        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:
            data = self.get_data_from_riak_item(self.with_retries(self.riak_bucket.get, key))
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
        if self.model_class:
            data = data.as_primitives()
        item = self.with_retries(self.riak_bucket.new, key=key, data=data, content_type='application/json')
        item.store()
        return True

    def delete(self, key):
        self.with_retries(self.riak_bucket.delete, key)

    def delete_matching(self, query):
        for item in self.stream_search(query, fl=self.datastore.ID):
            try:
                key = item.id
                self.with_retries(self.riak_bucket.delete, key)
            except AttributeError:
                key = item[self.datastore.ID]
                if isinstance(key, list):
                    for k in key:
                        self.with_retries(self.riak_bucket.delete, k)
                else:
                    self.with_retries(self.riak_bucket.delete, key)

        return True

    def _cleanup_search_result(self, item, fields=None):
        if isinstance(item, dict):
            item.pop('_version_', None)
            item.pop('_yz_id', None)
            item.pop('_yz_rt', None)
            item.pop('_yz_rb', None)
            item.pop(self.EXTRA_SEARCH_FIELD, None)

        if self.model_class:
            item_id = item.pop('_yz_rk', None)
            if not fields or '*' in fields:
                fields = self.stored_fields.keys()
            elif isinstance(fields, str):
                fields = fields.split(',')

            return self.model_class(item, mask=fields, docid=item_id)

        return {key: val if isinstance(val, list) else [val] for key, val in item.items()}

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

    def histogram(self, field, start, end, gap, query="*", mincount=1, filters=(), access_control=None):
        ret_val = super().histogram(field, start, end, gap, query=query, mincount=mincount,
                                    filters=filters, access_control=access_control)

        # NOTE: mincount does not seem to be applied correctly in the solr instance provided by riak
        #       we will apply mincount here

        return {step: count for step, count in ret_val.items() if count >= mincount}

    def fields(self, port=8093):
        return super().fields(self.solr_port)

    def _index_exists(self):
        try:
            self.datastore.client.get_search_index('name')
            return True
        except riak.RiakError:
            return False

    def _ensure_collection(self):
        # TODO: get schema and nvals from model_class
        if not self._index_exists():
            log.warning("Collection {collection} does not exists. "
                        "Creating it now...".format(collection=self.name.upper()))
            schema_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../support/riak/schema.xml"))
            with open(schema_path) as sf:
                schema_raw = sf.read()
            nval = 1

            schema_raw = schema_raw.replace('REPLACE_NAME', self.name.upper())

            if self.model_class:
                mapping = build_mapping(self.model_class.fields().values())
                schema_raw = schema_raw.replace('<!-- REPLACE_FIELDS -->', mapping)
            else:
                schema_raw = schema_raw.replace('<!-- REPLACE_FIELDS -->', self.DEFAULT_CATCH_ALL_FIELDS)

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
        self._check_fields()

    def wipe(self):
        log.warning("Wipe operation started for collection: %s" % self.name.upper())

        for items in self.with_retries(self.riak_bucket.stream_index, "$bucket", ""):
            for item in items:
                log.warning("{bucket}: deleting key [{key}]".format(bucket=self.name, key=item))
                self.with_retries(self.riak_bucket.delete, item)

        props = {
            'search_index': "_dont_index_"
        }
        self.datastore.client.set_bucket_props(bucket=self.riak_bucket, props=props)
        self.datastore.client.delete_search_index(self.name)


class RiakStore(SolrStore):
    """ Riak implementation of the ResultStore interface."""
    ID = "_yz_rk"

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

    def __getattr__(self, name) -> RiakCollection:
        if name not in self._collections:
            model_class = self._models[name]
            self._collections[name] = self._collection_class(self, name, model_class=model_class,
                                                             solr_port=self.solr_port,
                                                             riak_http_port=self.riak_http_port)
        return self._collections[name]

    # noinspection PyBroadException
    def ping(self):
        try: 
            return self.client.ping()
        except Exception:
            return False

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
