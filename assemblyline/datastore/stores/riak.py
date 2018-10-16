import json
import requests

from copy import copy
from urllib import quote, unquote

from assemblyline.al.core.datastore import BaseStore, config, DataStoreException, log, SearchException, \
    SearchRetryException, DatastoreObject
from assemblyline.al.core.bucket_logic import EXTRA_SEARCH_FIELD
from assemblyline.common.charset import safe_str
from assemblyline.common.datastore_reconnect import DatastoreReconnect, DatastoreObjectReconnect

DATASTORE_STREAM_PORT = config.datastore.riak.stream_port
DATASTORE_SOLR_PORT = config.datastore.riak.solr_port

riak = None


def utf8safe_encoder(obj):
    """
    This fixes riak unicode issues when strings in blob are already UTF-8.
    """
    return json.dumps(obj)


class RiakObject(DatastoreObject):
    def __init__(self, datastore, name):
        super(RiakObject, self).__init__(datastore, name)
        self.riak_bucket = datastore.client.bucket(name, bucket_type="data")

    def commit(self, host=None):
        url = "http://{host}:{port}/{path}/{bucket}/update/?commit=true" \
              "&softCommit=true&wt=json".format(host=host, port=self.datastore.solr_port,
                                                path=self.datastore.url_path, bucket=self.name)
        res = requests.get(url)

        if res.ok:
            solr_out = res.json()
            return solr_out
        else:
            return None

    # noinspection PyBroadException
    @staticmethod
    def get_data_from_riak_item(item, strict=False):
        if strict and not item.exists:
            raise DataStoreException("Key '{key}' does not exist in bucket {bucket}.".format(key=item.key,
                                                                                             bucket=item.bucket.name))
        if item.encoded_data == 'None':
            return None
        try:
            return item.data
        except Exception:
            if item.bucket.name != 'blob':
                log.exception("[bucket:'%s', key:'%s'] Invalid data was inserted in the index, using alternate"
                              "decoding method to pull the data." % (item.bucket.name, item.key))
            return item.encoded_data

    @DatastoreObjectReconnect(log)
    def get(self, key, strict=False):
        data = self.get_data_from_riak_item(self.riak_bucket.get(key), strict=strict)
        if data and isinstance(data, dict):
            data.pop(EXTRA_SEARCH_FIELD, None)
        return data

    @DatastoreObjectReconnect(log)
    def multiget(self, key_list, strict=False):
        temp_keys = copy(key_list)
        done = False
        retry = 0
        ret = []
        while not done:
            for bucket_item in self.riak_bucket.multiget(temp_keys):
                if not isinstance(bucket_item, tuple):
                    try:
                        item_data = RiakObject.get_data_from_riak_item(bucket_item, strict=strict)
                    except DataStoreException:
                        continue
                    if item_data is not None:
                        if isinstance(item_data, dict):
                            item_data.pop(EXTRA_SEARCH_FIELD, None)
                        ret.append(item_data)
                    temp_keys.remove(bucket_item.key)

            if len(temp_keys) == 0:
                done = True
            else:
                retry += 1

            if retry >= BaseStore.MAX_RETRY:
                raise DataStoreException("%s is missing data for the following keys: %s" % (self.name.upper(),
                                                                                            temp_keys))
        return ret

    def _save(self, key, data):
        item = self.riak_bucket.new(key=key, data=data, content_type='application/json')
        item.store()

    @DatastoreObjectReconnect(log)
    def keys(self, access_control=None):
        out = []
        for item in self.datastore.stream_search(self.name, "*", fl=self.datastore.ID, access_control=access_control):
            out.append(item[self.datastore.ID])
        return list(set(out))

    @DatastoreObjectReconnect(log)
    def stream_keys(self, **_):
        for items in self.riak_bucket.stream_index("$bucket", ""):
            for item in items:
                yield item

    @DatastoreObjectReconnect(log)
    def delete(self, key):
        self.riak_bucket.delete(key)


class RiakStore(BaseStore):
    """ Riak implementation of the ResultStore interface."""

    ID = "_yz_rk"
    DEFAULT_SORT = "_yz_id asc"

    READ_TIMEOUT_MILLISECS = 30000
    CURRENT_QUERY_PLAN = {}

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
    def __init__(self, hosts=None, port=config.datastore.riak.port, protocol_used='pbc', filestore_factory=None):
        global riak
        if riak is None:
            import riak

        super(RiakStore, self).__init__(hosts or self.get_db_node_list(), filestore_factory)

        self.port = port or config.datastore.riak.port
        self.stream_port = DATASTORE_STREAM_PORT
        self.solr_port = DATASTORE_SOLR_PORT

        # Init Client
        self.riak_nodes = [{'host': n, 'pb_port': self.port, 'http_port': DATASTORE_STREAM_PORT} for n in self.hosts]
        self.client = riak.RiakClient(protocol=protocol_used, nodes=self.riak_nodes)
        log.debug('riakclient opened...')

        # Set default encoders
        self.client.set_encoder('application/json', utf8safe_encoder)
        self.client.set_encoder('text/json', utf8safe_encoder)

        # Set default resolver
        self.client.resolver = riak.resolver.last_written_resolver

        # Initialize buckets
        self._alerts = RiakObject(self, "alert")
        self._blobs = RiakObject(self, "blob")
        self._emptyresults = RiakObject(self, "emptyresult")
        self._errors = RiakObject(self, "error")
        self._files = RiakObject(self, "file")
        self._filescores = RiakObject(self, "filescore")
        self._nodes = RiakObject(self, "node")
        self._results = RiakObject(self, "result")
        self._signatures = RiakObject(self, "signature")
        self._submissions = RiakObject(self, "submission")
        self._users = RiakObject(self, "user")
        self._workflows = RiakObject(self, "workflow")
        self._apply_proxies()

        self.protocol_used = protocol_used
        self.url_path = "internal_solr"

    def __str__(self):
        return '{0} - {1}:{2}'.format(
            self.__class__.__name__,
            self.hosts,
            self.port)

    # noinspection PyBroadException
    def datastore_connection_reset(self):
        global riak
        if riak is None:
            import riak

        try:
            if not self.client.ping():
                self.client.close()
                self.client = None
                self.client = riak.RiakClient(protocol=self.protocol_used, nodes=self.riak_nodes)
        except Exception:
            pass

    # noinspection PyBroadException
    def advanced_search(self, bucket, query, args, df="text", wt="json", save_qp=False, access_control=None,
                        _hosts_=None, filters=()):

        if bucket not in BaseStore.ALL_INDEXED_BUCKET_LIST:
            raise SearchException("Bucket %s does not exists." % bucket)

        host_list = copy(_hosts_ or self.hosts)

        args = list(args)
        if filters:
            if isinstance(filters, basestring):
                args.append(('fq', filters))
            else:
                args.extend(('fq', ff) for ff in filters)

        try:
            query = quote(query)
        except Exception:
            raise SearchException("Unable to URL quote query: %s" % safe_str(query))

        while True:
            session, host, _ = self.get_or_create_session(host_list, self.stream_port)
            try:
                kw = "&".join(["%s=%s" % (k, quote(safe_str(v))) for k, v in args if self.valid_solr_param(k, v)])
                url = "http://%s/search/query/%s/?q=%s&df=%s&wt=%s" % (host, bucket, query, df, wt)

                if access_control:
                    url += "&fq=%s" % access_control

                if kw:
                    url += "&" + kw

                res = session.get(url)
                if res.ok:
                    solr_out = res.json()

                    # Cleanup potential leak of information about our cluster
                    qp_fields = {}
                    params = [k for k in solr_out.get("responseHeader", {}).get("params", {}).keys()]
                    for k in params:
                        if ":%s" % DATASTORE_SOLR_PORT in k or ":8093" in k or k == "shards":
                            if save_qp:
                                qp_fields[k] = solr_out["responseHeader"]["params"][k]
                            del solr_out["responseHeader"]["params"][k]

                    if save_qp:
                        self.CURRENT_QUERY_PLAN[bucket] = "&%s" % "&".join(["%s=%s" % (k, v)
                                                                            for k, v in qp_fields.iteritems()])

                    return solr_out
                else:
                    try:
                        solr_error = res.json()
                        message = solr_error["error"]["msg"]
                        if "IOException" in message or "Server refused" in message:
                            raise SearchRetryException()
                        else:
                            if "neither indexed nor has doc values: " in message:
                                # Cleanup potential leak of information about our cluster
                                qp_fields = {}
                                params = [k for k in solr_error.get("responseHeader", {}).get("params", {}).keys()]
                                for k in params:
                                    if ":%s" % DATASTORE_SOLR_PORT in k or ":8093" in k or k == "shards":
                                        if save_qp:
                                            qp_fields[k] = solr_error["responseHeader"]["params"][k]
                                        del solr_error["responseHeader"]["params"][k]

                                if save_qp:
                                    self.CURRENT_QUERY_PLAN[bucket] = "&%s" % "&".join(["%s=%s" % (k, v)
                                                                                        for k, v in
                                                                                        qp_fields.iteritems()])
                                return solr_error
                            else:
                                raise SearchException(message)
                    except SearchException:
                        raise
                    except Exception:
                        if res.status_code == 404:
                            raise SearchException("Bucket %s does not exists." % bucket)
                        elif res.status_code == 500:
                            raise SearchRetryException()
                        else:
                            raise SearchException("bucket: %s, query: %s, args: %s\n%s" %
                                                  (bucket, query, args, res.content))
            except requests.ConnectionError:
                host_list.remove(host)
            except SearchRetryException:
                host_list.remove(host)
            finally:
                if save_qp:
                    self.terminate_session(host)

    def close(self):
        super(RiakStore, self).close()

        if self.client:
            log.debug('riakclient closed...')
            self.client.close()
            self.client = None

    def direct_search(self, bucket, query, args=(), df="text", wt="json", access_control=None,
                      url_extra=None, _hosts_=None, filters=()):
        if bucket not in self.CURRENT_QUERY_PLAN or not self.CURRENT_QUERY_PLAN[bucket]:
            log.debug("There is no coverage plan for bucket '%s'. Re-dispatching to advanced_search and saving the "
                      "coverage plan..." % bucket)
            riak_out = self.advanced_search(bucket, query, args, df=df, wt=wt, save_qp=True,
                                            access_control=access_control, _hosts_=_hosts_, filters=filters)
            log.debug("Coverage plan for '%s' saved as: %s" % (bucket, self.CURRENT_QUERY_PLAN[bucket]))
            riak_out['provider'] = "RIAK"
            return riak_out

        try:
            return super(RiakStore, self).direct_search(bucket, query, args, df, wt, access_control, filters=filters,
                                                        url_extra=self.CURRENT_QUERY_PLAN[bucket], _hosts_=_hosts_)

        except requests.ConnectionError:
            riak_out = self.advanced_search(bucket, unquote(query), args, df=df, wt=wt, save_qp=True,
                                            access_control=access_control, filters=filters)
            riak_out['provider'] = "RIAK"
            return riak_out
        except SearchRetryException:
            riak_out = self.advanced_search(bucket, unquote(query), args, df=df, wt=wt, save_qp=True,
                                            access_control=access_control, filters=filters)
            riak_out['provider'] = "RIAK"
            return riak_out

    def get_db_node_list(self, full=True):
        if full:
            return config.datastore.riak.nodes
        return config.datastore.hosts
