import json
import os
import uuid
from urllib.parse import quote

import requests
import time
import threading

from copy import copy, deepcopy
from random import choice

from assemblyline.common.chunk import chunked_list
from assemblyline.common.memory_zip import InMemoryZip
from assemblyline.common.str_utils import safe_str
from assemblyline.datastore import BaseStore, log, Collection, DataStoreException, SearchException, SearchRetryException
from assemblyline.datastore.reconnect import collection_reconnect


class SolrCollection(Collection):
    SOLR_GET_TIMEOUT_SEC = 5
    MULTIGET_MAX_RETRY = 5
    MAX_SEARCH_ROWS = 500
    MAX_GROUP_LIMIT = 10
    MAX_FACET_LIMIT = 100
    EXTRA_SEARCH_FIELD = '__text__'
    DEFAULT_SORT = "_id_ asc"

    COMMIT_WITHIN_MAP = {
        "alert": 60000,
        "error": 60000,
        "filescore": 120000,
        "submission": 30000,
        "file": 60000,
        "emptyresult": 120000,
        "result": 60000,
        "_default_": 1000
    }

    ######################################
    # SOLR only methods
    def _get_session(self):
        session, host = self.datastore.get_or_create_session()
        if ":" not in host:
            host += ":8983"
        return session, host

    #####################################
    # Overloaded functions
    def __init__(self, datastore, name, model_class=None, api_base="solr", replication_factor=1, num_shards=1):
        self.api_base = api_base
        self.num_shards = replication_factor
        self.replication_factor = num_shards
        super().__init__(datastore, name, model_class=model_class)

    @collection_reconnect(log)
    def commit(self):
        for host in self.datastore.get_hosts():
            if ":" not in host:
                host += ":8983"
            url = "http://{host}/{api_base}/{core}/update/?commit=true" \
                  "&softCommit=true&wt=json".format(host=host, api_base=self.api_base, core=self.name)

            res = requests.get(url)
            return res.ok

    @collection_reconnect(log)
    def multiget(self, key_list):
        temp_keys = copy(key_list)
        done = False
        retry = 0
        ret = []

        while not done:
            session, host = self._get_session()

            url = "http://{host}/{api_base}/{core}/get?ids={keys}" \
                  "&wt=json&fl=_source_,{id_field}".format(host=host, api_base=self.api_base, core=self.name,
                                                           keys=','.join(temp_keys), id_field=self.datastore.ID)

            res = session.get(url, timeout=self.SOLR_GET_TIMEOUT_SEC)
            if res.ok:
                for doc in res.json().get('response', {}).get('docs', []):
                    if doc:
                        data = doc.get("_source_", None)
                        try:
                            data = json.loads(data)
                            if isinstance(data, dict):
                                data.pop(self.EXTRA_SEARCH_FIELD, None)
                            ret.append(self.normalize(data))
                        except ValueError:
                            ret.append(self.normalize(data))
                        temp_keys.remove(doc.get(self.datastore.ID, None))

            if len(temp_keys) == 0:
                done = True
            else:
                retry += 1

            if retry >= SolrCollection.MULTIGET_MAX_RETRY:
                raise DataStoreException("%s is missing data for the following keys: %s" % (self.name.upper(),
                                                                                            temp_keys))

        return ret

    def _get(self, key, retries=None):
        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:
            session, host = self._get_session()

            url = "http://{host}/{api_base}/{core}/get?id={key}&wt=json&fl=_source_".format(
                host=host, api_base=self.api_base, core=self.name, key=key)

            res = session.get(url, timeout=self.SOLR_GET_TIMEOUT_SEC)
            if res.ok:
                doc = res.json().get('doc', None)
                if doc:
                    data = doc.get("_source_", None)
                    try:
                        data = json.loads(data)
                        if isinstance(data, dict):
                            data.pop(self.EXTRA_SEARCH_FIELD, None)
                        return data
                    except ValueError:
                        return data

            if retries > 0:
                time.sleep(0.05)
                retries -= 1
            elif retries < 0:
                time.sleep(0.05)
            else:
                done = True

        return None

    def _save(self, key, source_data):
        data = deepcopy(source_data)
        if not isinstance(data, dict):
            data = {"_source_": json.dumps(data)}
        else:
            data["_source_"] = json.dumps(data)
        data[self.datastore.ID] = key
        commit_within = int(self.COMMIT_WITHIN_MAP.get(self.name, None) or self.COMMIT_WITHIN_MAP["_default_"])

        session, host = self._get_session()
        url = "http://{host}/{api_base}/{core}/update/json" \
              "/docs?commitWithin={cw}&overwrite=true".format(host=host, api_base=self.api_base,
                                                              core=self.name, cw=commit_within)
        res = session.post(url, data=json.dumps(data), headers={"content-type": "application/json"})
        if not res.ok:
            try:
                raise DataStoreException(res.json())
            except Exception:
                raise DataStoreException(res.text)

    @collection_reconnect(log)
    def delete(self, key):
        data = {"delete": {"id": key}}
        commit_within = int(self.COMMIT_WITHIN_MAP.get(self.name, None) or self.COMMIT_WITHIN_MAP["_default_"])

        session, host = self._get_session()
        url = "http://{host}/{api_base}/{core}/update?commitWithin={cw}&overwrite=true".format(host=host,
                                                                                               api_base=self.api_base,
                                                                                               core=self.name,
                                                                                               cw=commit_within)
        res = session.post(url, data=json.dumps(data), headers={"content-type": "application/json"})
        return res.ok

    def _valid_solr_param(self, key, value):
        msg = "Invalid parameter (%s=%s). Should be between %d and %d"

        if key.endswith('facet.offset') or key.endswith('group.offset'):
            return False
        if key.endswith('facet.limit') and not 1 <= int(value) <= self.MAX_FACET_LIMIT:
            raise SearchException(msg % (key, value, 1, self.MAX_FACET_LIMIT))
        if key.endswith('group.limit') and not 1 <= int(value) <= self.MAX_GROUP_LIMIT:
            raise SearchException(msg % (key, value, 1, self.MAX_GROUP_LIMIT))
        if key == 'rows' and not 0 <= int(value) <= self.MAX_SEARCH_ROWS:
            raise SearchException(msg % (key, value, 0, self.MAX_SEARCH_ROWS))

        return True

    @staticmethod
    def _get_value(searched_key, args):
        for (key, value) in args:
            if key == searched_key:
                return value

        return None

    def _cleanup_search_result(self, item):
        if isinstance(item, dict):
            item.pop('_source_', None)
            item.pop('_version_', None)
            item.pop(self.EXTRA_SEARCH_FIELD, None)

        return item

    # noinspection PyBroadException
    @collection_reconnect(log)
    def _search(self, args=None):
        if not isinstance(args, list):
            raise SearchException('args needs to be a list of tuples')

        session, host = self._get_session()

        query = self._get_value('q', args)

        if not query:
            raise SearchException("You must specify a query")

        rows = self._get_value('rows', args)

        if not rows:
            rows = self.DEFAULT_ROW_SIZE
            args.append(('rows', rows))

        kw = "&".join(["%s=%s" % (param_name, quote(safe_str(param_value, force_str=True)))
                       for param_name, param_value in args if self._valid_solr_param(param_name, param_value)])
        url = "http://{host}/{api_base}/{collection}/select/?".format(host=host,
                                                                      api_base=self.api_base,
                                                                      collection=self.name)
        if kw:
            url += kw

        res = session.get(url)
        if res.ok:
            return res.json()
        else:
            try:
                solr_error = res.json()
                message = solr_error["error"]["msg"]
                if "IOException" in message or "Server refused" in message:
                    raise SearchRetryException()
                else:
                    if "neither indexed nor has doc values: " in message:
                        return solr_error
                    else:
                        raise SearchException(message)
            except SearchException:
                raise
            except Exception:
                if res.status_code == 404:
                    raise SearchException("Collection %s does not exists." % self.name)
                elif res.status_code == 500:
                    raise SearchRetryException()
                else:
                    raise SearchException("Collection: %s, query: %s, args: %s\n%s" %
                                          (self.name, query, args, res.content))

    def search(self, query, offset=0, rows=Collection.DEFAULT_ROW_SIZE, sort=DEFAULT_SORT,
               fl=None, timeout=None, filters=(), access_control=None):

        args = [
            ('q', query),
            ('start', offset),
            ('rows', rows),
            ('sort', sort)
        ]

        if fl:
            args.append(('fl', fl))

        if timeout:
            args.append(('timeAllowed', timeout))

        if filters:
            if isinstance(filters, list):
                args.extend(('fq', ff) for ff in filters)
            else:
                args.append(('fq', filters))

        if access_control:
            args.append(('fq', access_control))

        data = self._search(args)
        output = {
            "offset": int(data['response']['start']),
            "rows": int(rows),
            "total": int(data['response']['numFound']),
            "items": [self._cleanup_search_result(x) for x in data['response']['docs']]
        }
        return output

    @collection_reconnect(log)
    def stream_search(self, query, sort=DEFAULT_SORT, fl=None, filters=(), access_control=None, buffer_size=200):

        def _auto_fill(_items, _lock, _args):
            page_size = self._get_value('rows', args)
            _max_yield_cache = 50000

            done = False
            while not done:
                skip = False
                with lock:
                    if len(_items) > _max_yield_cache:
                        skip = True

                if skip:
                    time.sleep(0.01)
                    continue

                data = self._search(_args)

                # Replace cursorMark.
                _args = _args[:-1]
                _args.append(('cursorMark', data.get('nextCursorMark', '*')))

                with _lock:
                    _items.extend([self._cleanup_search_result(x) for x in data['response']['docs']])

                done = int(page_size) - len(data['response']['docs'])

        if buffer_size > 500 or buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 500.")

        if query in ["*", "*:*"] and fl != self.datastore.ID:
            raise SearchException("You did not specified a query, you just asked for everything... Play nice.")

        args = [
            ('q', query),
            ('sort', sort),
            ("rows", str(buffer_size))
        ]

        if fl:
            args.append(('fl', fl))

        if filters:
            if isinstance(filters, list):
                args.extend(('fq', ff) for ff in filters)
            else:
                args.append(('fq', filters))

        if access_control:
            args.append(('fq', access_control))

        args.append(('cursorMark', '*'))

        yield_done = False
        items = []
        lock = threading.Lock()
        sf_t = threading.Thread(target=_auto_fill,
                                args=[items, lock, args],
                                name="stream_search_%s" % uuid.uuid4().hex)
        sf_t.setDaemon(True)
        sf_t.start()
        while not yield_done:
            try:
                with lock:
                    item = items.pop(0)

                yield item
            except IndexError:
                if not sf_t.is_alive() and len(items) == 0:
                    yield_done = True
                time.sleep(0.01)

    @collection_reconnect(log)
    def keys(self, access_control=None):
        for item in self.stream_search("*", fl=self.datastore.ID, access_control=access_control):
            yield item[self.datastore.ID]

    @collection_reconnect(log)
    def histogram(self, field, query, start, end, gap, mincount, filters=(), access_control=None):
        """Build a histogram of `query` data over `field`"""
        args = [
            ("rows", "0"),
            ("facet", "on"),
            ("facet.range", field),
            ("facet.range.start", start),
            ("facet.range.end", end),
            ("facet.range.gap", gap),
            ("facet.mincount", mincount),
            ("q", query)
        ]
        if filters:
            if isinstance(filters, list):
                args.extend(('fq', ff) for ff in filters)
            else:
                args.append(('fq', filters))

        result = self._search(args)
        return dict(chunked_list(result["facet_counts"]["facet_ranges"][field]["counts"], 2))

    @collection_reconnect(log)
    def grouped_search(self, query, group_on, start=None, sort=None, group_sort=None, fields=None, rows=None,
                       filters=(), access_control=None):
        pass

    def _get_configset(self):
        schema = os.path.abspath(os.path.join(os.path.dirname(__file__), "../support/solr/managed-schema"))
        cfg = os.path.abspath(os.path.join(os.path.dirname(__file__), "../support/solr/solrconfig.xml"))

        with open(schema, 'rb') as fh:
            schema_raw = fh.read()

        with open(cfg, 'rb') as fh:
            cfg_raw = fh.read()

        if self.model_class is None:
            zobj = InMemoryZip()
            zobj.append('managed-schema', schema_raw)
            zobj.append('solrconfig.xml', cfg_raw)
            return zobj.read()
        else:
            # TODO: Build a configset based on the model
            pass

        return None

    @collection_reconnect(log)
    def _ensure_configset(self):
        session, host = self._get_session()
        test_url = "http://{host}/{api_base}/admin/configs?action=LIST".format(host=host, api_base=self.api_base)
        res = session.get(test_url, headers={"content-type": "application/json"})
        if res.ok:
            data = res.json()
            if self.name not in data.get('configSets', []):
                log.info("ConfigSet {collection} does not exists. "
                         "Creating it now...".format(collection=self.name.upper()))
                upload_url = "http://{host}/{api_base}/admin/configs?action=UPLOAD" \
                             "&name={collection}".format(host=host, api_base=self.api_base, collection=self.name)
                res = session.post(upload_url, data=self._get_configset(), headers={"content-type": "application/json"})
                if res.ok:
                    log.info("Configset {collection} created!".format(collection=self.name))
                else:
                    raise DataStoreException("Could not create configset {collection}.".format(collection=self.name))
        else:
            raise DataStoreException("Cannot get to configset admin page.")

    @collection_reconnect(log)
    def _ensure_collection(self):
        session, host = self._get_session()
        test_url = "http://{host}/{api_base}/admin/collections?action=LIST".format(host=host, api_base=self.api_base)
        res = session.get(test_url, headers={"content-type": "application/json"})
        if res.ok:
            data = res.json()
            if self.name not in data.get('collections', []):
                # Make sure configset for collection exists
                self._ensure_configset()

                # Create collection
                log.warn("Collection {collection} does not exists. "
                         "Creating it now...".format(collection=self.name.upper()))
                create_url = "http://{host}/{api_base}/admin/collections?action=CREATE" \
                             "&name={collection}&numShards={shards}&replicationFactor={replication}" \
                             "&collection.configName={collection}".format(host=host,
                                                                          api_base=self.api_base,
                                                                          collection=self.name,
                                                                          shards=self.num_shards,
                                                                          replication=self.replication_factor)
                res = session.get(create_url, headers={"content-type": "application/json"})
                if res.ok:
                    log.info("Collection {collection} created!".format(collection=self.name))
                else:
                    raise DataStoreException("Could not create collection {collection}.".format(collection=self.name))
        else:
            raise DataStoreException("Cannot get to collection admin page.")


class SolrStore(BaseStore):
    """ SOLR implementation of the ResultStore interface."""
    ID = "_id_"
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

    def __init__(self, hosts):
        super().__init__(hosts, SolrCollection)
        self.HTTP_SESSION_POOL = {}

    def __str__(self):
        return '{0} - {1}'.format(
            self.__class__.__name__,
            self._hosts)

    def is_alive(self):
        with requests.Session() as cur_session:
            for host in self._hosts:
                try:
                    res = cur_session.get('http://{host}/solr/admin/cores?action=STATUS'.format(host=host))
                    if not res.ok:
                        return False
                except requests.ConnectionError:
                    return False

        return True

    def close(self):
        super().close()
        for thread_id in self.HTTP_SESSION_POOL.keys():
            self._terminate_session(thread_id)

    def _terminate_session(self, thread_id):
        log.debug("Closing HTTP session for thread id: %s..." % thread_id)
        if thread_id in self.HTTP_SESSION_POOL:
            self.HTTP_SESSION_POOL[thread_id].close()
            del self.HTTP_SESSION_POOL[thread_id]

    def get_or_create_session(self):
        thread_id = threading.get_ident()
        host = choice(self._hosts)
        session = self.HTTP_SESSION_POOL.get(thread_id, None)
        if not session:
            log.debug("Creating new HTTP session for %s..." % host)
            session = requests.Session()
            self.HTTP_SESSION_POOL[thread_id] = session

        return session, host

    def connection_reset(self):
        self._terminate_session(threading.get_ident())


if __name__ == "__main__":
    s = SolrStore(['127.0.0.1:8983'])
    s.register('user')
    if not s.user.get('sgaron'):
        s.user.save('sgaron', {'uname': 'sgaron', 'is_admin': True})
    print(s.user.get('sgaron'))
    print(s.user.multiget(['sgaron']))
    print(s.user.search("*:*"))
    print(s.user.search("*:*", fl="*"))

    for k in s.user.keys():
        print(k)
    print(s.user.histogram('_version_', "*", 1614679643837693700, 1614679643837694200, 100, 0))
    print(s.user._search([('q', "*:*")]))
    print(s.user._search([('q', "*:*"), ('fl', "*")]))
