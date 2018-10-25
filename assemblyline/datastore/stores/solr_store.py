import json
import os
import requests
import time
import threading
import uuid

from copy import copy, deepcopy
from datemath import dm
from datemath.helpers import DateMathException
from random import choice
from urllib.parse import quote

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

    def __init__(self, datastore, name, model_class=None, api_base="solr", replication_factor=1, num_shards=1):
        self.api_base = api_base
        self.num_shards = replication_factor
        self.replication_factor = num_shards
        super().__init__(datastore, name, model_class=model_class)

    def _get_session(self, port=8983):
        session, host = self.datastore.get_or_create_session()
        if ":" not in host:
            host += ":%s" % port
        return session, host

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

    def _get(self, key, retries):
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

        banned_suffix = [
            'facet.offset',
            'group.offset',
            'facet.enum.cache.minDf',
            'facet.range.hardend',
            'facet.range.include',
            'facet.range.other',
            'facet.range.method',
            'facet.missing',
            'facet.overrequest.count',
            'facet.overrequest.ratio',
            'facet.threads',
            'facet.method',
        ]

        banned_prefix = [
            'facet.interval',
            'facet.pivot'
        ]

        for banned in banned_suffix:
            if key.endswith(banned):
                return False

        for banned in banned_prefix:
            if key.startswith(banned):
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
    def _search(self, args=None, port=8983, api_base=None, search_api='select/'):
        if not isinstance(args, list):
            raise SearchException('args needs to be a list of tuples')

        session, host = self._get_session(port)

        query = self._get_value('q', args)

        if not query:
            raise SearchException("You must specify a query")

        rows = self._get_value('rows', args)

        if not rows:
            rows = self.DEFAULT_ROW_SIZE
            args.append(('rows', rows))

        kw = "&".join(["%s=%s" % (param_name, quote(safe_str(param_value, force_str=True)))
                       for param_name, param_value in args if self._valid_solr_param(param_name, param_value)])
        url = "http://{host}/{api_base}/{collection}/{search_api}?".format(host=host,
                                                                           api_base=api_base or self.api_base,
                                                                           collection=self.name,
                                                                           search_api=search_api)
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

    def search(self, query, offset=0, rows=None, sort=None,
               fl=None, timeout=None, filters=(), access_control=None):

        if not rows:
            rows = self.DEFAULT_ROW_SIZE

        if not sort:
            sort = self.DEFAULT_SORT

        args = [
            ('q', query),
            ('start', offset),
            ('rows', rows),
            ('sort', sort),
            ('wt', 'json'),
            ('df', '__text__')
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

    def stream_search(self, query, fl=None, filters=(), access_control=None, buffer_size=200):

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
            ('sort', self.DEFAULT_SORT),
            ("rows", str(buffer_size)),
            ('wt', 'json'),
            ('df', '__text__')
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

    def keys(self, access_control=None):
        for item in self.stream_search("*", fl=self.datastore.ID, access_control=access_control):
            yield item[self.datastore.ID]

    @staticmethod
    def _to_python_datemath(value):
        replace_list = [
            (SolrStore.DATE_FORMAT['NOW'], SolrStore.DATEMATH_MAP['NOW']),
            (SolrStore.DATE_FORMAT['YEAR'], SolrStore.DATEMATH_MAP['YEAR']),
            (SolrStore.DATE_FORMAT['MONTH'], SolrStore.DATEMATH_MAP['MONTH']),
            (SolrStore.DATE_FORMAT['WEEK'], SolrStore.DATEMATH_MAP['WEEK']),
            (SolrStore.DATE_FORMAT['DAY'], SolrStore.DATEMATH_MAP['DAY']),
            (SolrStore.DATE_FORMAT['HOUR'], SolrStore.DATEMATH_MAP['HOUR']),
            (SolrStore.DATE_FORMAT['MINUTE'], SolrStore.DATEMATH_MAP['MINUTE']),
            (SolrStore.DATE_FORMAT['SECOND'], SolrStore.DATEMATH_MAP['SECOND']),
            (SolrStore.DATE_FORMAT['DATE_END'], SolrStore.DATEMATH_MAP['DATE_END'])
        ]

        for x in replace_list:
            value = value.replace(*x)

        return value

    # noinspection PyBroadException
    def _validate_steps_count(self, start, end, gap):
        gaps_count = None
        try:
            start = int(start)
            end = int(end)
            gap = int(gap)

            gaps_count = int((end - start) / gap)
        except ValueError:
            pass

        if not gaps_count:
            try:
                parsed_start = dm(self._to_python_datemath(start)).timestamp
                parsed_end = dm(self._to_python_datemath(end)).timestamp
                parsed_gap = dm(self._to_python_datemath(gap)).timestamp - dm('now').timestamp

                gaps_count = int((parsed_end - parsed_start) / parsed_gap)
            except DateMathException:
                pass

        if not gaps_count:
            raise SearchException(
                "Could not parse date ranges. (start='%s', end='%s', gap='%s')" % (start, end, gap))

        if gaps_count > self.MAX_FACET_LIMIT:
            raise SearchException('Facet max steps are limited to %s. '
                                  'Current settings would generate %s steps' % (self.MAX_FACET_LIMIT,
                                                                                gaps_count))

    def histogram(self, field, start, end, gap, query="*", mincount=1, filters=(), access_control=None):
        """Build a histogram of `query` data over `field`"""

        self._validate_steps_count(start, end, gap)

        args = [
            ("rows", "0"),
            ("facet", "on"),
            ("facet.range", field),
            ("facet.range.start", start),
            ("facet.range.end", end),
            ("facet.range.gap", gap),
            ("facet.mincount", mincount),
            ("q", query),
            ('wt', 'json'),
            ('df', '__text__')
        ]

        if filters:
            if isinstance(filters, list):
                args.extend(('fq', ff) for ff in filters)
            else:
                args.append(('fq', filters))

        if access_control:
            args.append(('fq', access_control))

        result = self._search(args)
        return dict(chunked_list(result["facet_counts"]["facet_ranges"][field]["counts"], 2))

    def field_analysis(self, field, query="*", prefix=None, contains=None, ignore_case=False, sort=None,
                       limit=10, min_count=1, filters=(), access_control=None):

        if not sort:
            sort = self.DEFAULT_SORT

        args = [
            ("q", query),
            ("rows", "0"),
            ("facet", "on"),
            ("facet.field", field),
            ("facet.limit", limit),
            ("facet.mincount", min_count),
            ('wt', 'json'),
            ('df', '__text__')
        ]

        if prefix:
            args.append(("facet.prefix", prefix))

        if contains:
            args.append(("facet.contains", contains))

        if ignore_case:
            args.append(("facet.contains.ignore_case", 'true'))

        if sort:
            args.append(("facet.sort", sort))

        if filters:
            if isinstance(filters, list):
                args.extend(('fq', ff) for ff in filters)
            else:
                args.append(('fq', filters))

        if access_control:
            args.append(('fq', access_control))

        result = self._search(args)
        return dict(chunked_list(result["facet_counts"]["facet_fields"][field], 2))

    def grouped_search(self, field, query="*", offset=None, sort=None, group_sort=None, fl=None, limit=1,
                       rows=None, filters=(), access_control=None):

        if not sort:
            sort = self.DEFAULT_SORT

        if not rows:
            rows = self.DEFAULT_ROW_SIZE

        args = [
            ("group", "on"),
            ("group.field", field),
            ('rows', rows),
            ('q', query),
            ('wt', 'json'),
            ('df', '__text__')
        ]

        if offset:
            args.append(("start", offset))

        if sort:
            args.append(("sort", sort))

        if group_sort:
            args.append(("group.sort", group_sort))

        if fl:
            args.append(("fl", fl))

        if limit:
            args.append(('group.limit', limit))

        if filters:
            if isinstance(filters, list):
                args.extend(('fq', ff) for ff in filters)
            else:
                args.append(('fq', filters))

        if access_control:
            args.append(('fq', access_control))

        data = self._search(args)['grouped'][field]

        return {
            'offset': offset,
            'rows': rows,
            'total': data['matches'],
            'items': [{
                'value': grouping['groupValue'],
                'total': grouping['doclist']['numFound'],
                'items': [self._cleanup_search_result(x) for x in grouping['doclist']['docs']]
            } for grouping in data['groups']]
        }

    # noinspection PyBroadException
    @collection_reconnect(log)
    def fields(self):
        session, host = self._get_session()

        url = "http://{host}/{api_base}/{collection}/admin/luke/?wt=json".format(host=host,
                                                                                 api_base=self.api_base,
                                                                                 collection=self.name)
        res = session.get(url)
        if res.ok:
            collection_data = {}
            j = res.json()

            fields = j.get("fields", {})
            for field_name, field_value in fields.items():
                if field_value.get("docs", 0) == 0:
                    continue
                if field_name.startswith("_") or "//" in field_name:
                    continue
                if not Collection.FIELD_SANITIZER.match(field_name):
                    continue

                collection_data[field_name] = {
                    "indexed": field_value.get("schema", "").startswith("I"),
                    "stored": field_value.get("schema", "")[:3].endswith("S"),
                    "list": field_value.get("schema", "")[:5].endswith("M"),
                    "type": field_value.get("type", "")
                }

            return collection_data
        else:
            try:
                j = res.json()
                message = j["error"]["msg"]
                if "IOException" in message or "Server refused" in message:
                    raise SearchRetryException()
                else:
                    raise SearchException(message)
            except SearchException:
                raise
            except Exception:
                if res.status_code == 404:
                    return {}
                elif res.status_code == 500:
                    raise SearchRetryException()
                else:
                    raise SearchException(res.content)

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
    def _configset_exist(self, session=None, host=None):
        if session is None or host is None:
            session, host = self._get_session()

        test_url = "http://{host}/{api_base}/admin/configs?action=LIST".format(host=host, api_base=self.api_base)
        res = session.get(test_url, headers={"content-type": "application/json"})
        if res.ok:
            data = res.json()
            if self.name not in data.get('configSets', []):
                return False
            return True
        else:
            raise DataStoreException("Cannot get to configset admin page.")

    @collection_reconnect(log)
    def _ensure_configset(self, session=None, host=None):
        if session is None or host is None:
            session, host = self._get_session()

        if not self._configset_exist(session=session, host=host):
            log.info("ConfigSet {collection} does not exists. "
                     "Creating it now...".format(collection=self.name.upper()))
            upload_url = "http://{host}/{api_base}/admin/configs?action=UPLOAD" \
                         "&name={collection}".format(host=host, api_base=self.api_base, collection=self.name)
            res = session.post(upload_url, data=self._get_configset(), headers={"content-type": "application/json"})
            if res.ok:
                log.info("Configset {collection} created!".format(collection=self.name))
            else:
                raise DataStoreException("Could not create configset {collection}.".format(collection=self.name))

    @collection_reconnect(log)
    def _collection_exist(self, session=None, host=None):
        if session is None or host is None:
            session, host = self._get_session()

        test_url = "http://{host}/{api_base}/admin/collections?action=LIST".format(host=host, api_base=self.api_base)
        res = session.get(test_url, headers={"content-type": "application/json"})
        if res.ok:
            data = res.json()
            if self.name not in data.get('collections', []):
                return False
            return True
        else:
            raise DataStoreException("Cannot get to collection admin page.")

    @collection_reconnect(log)
    def _ensure_collection(self):
        session, host = self._get_session()

        # Make sure configset for collection exists
        self._ensure_configset(session=session, host=host)

        if not self._collection_exist(session=session, host=host):
            # Create collection
            log.warning("Collection {collection} does not exists. "
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

    @collection_reconnect(log)
    def wipe(self):
        log.warning("Wipe operation started for collection: %s" % self.name.upper())
        session, host = self._get_session()

        if self._collection_exist(session=session, host=host):
            log.warning("Removing collection: {collection}".format(collection=self.name.upper()))

            delete_url = "http://{host}/{api_base}/admin/collections?action=DELETE" \
                         "&name={collection}".format(host=host, api_base=self.api_base,
                                                     collection=self.name)
            res = session.get(delete_url, headers={"content-type": "application/json"})
            if res.ok:
                log.warning("Collection {collection} deleted!".format(collection=self.name))
            else:
                raise DataStoreException("Could not create collection {collection}.".format(collection=self.name))

        if self._configset_exist(session=session, host=host):
            log.warning("Removing configset: {collection}".format(collection=self.name.upper()))
            delete_url = "http://{host}/{api_base}/admin/configs?action=DELETE" \
                         "&name={collection}".format(host=host, api_base=self.api_base, collection=self.name)
            res = session.post(delete_url, data=self._get_configset(), headers={"content-type": "application/json"})
            if res.ok:
                log.warning("Configset {collection} deleted!".format(collection=self.name))
            else:
                raise DataStoreException("Could not delete configset {collection}.".format(collection=self.name))


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
        'DATE_END': 'Z'
    }

    def __init__(self, hosts, collection_class=SolrCollection, port=8983):
        super().__init__(hosts, collection_class)
        self.HTTP_SESSION_POOL = {}
        self.solr_port = port

    def __str__(self):
        return '{0} - {1}'.format(
            self.__class__.__name__,
            self._hosts)

    def ping(self):
        with requests.Session() as cur_session:
            for host in self._hosts:
                if ":" not in host:
                    host += ":%s" % self.solr_port
                try:
                    res = cur_session.get('http://{host}/solr/admin/cores?action=STATUS'.format(host=host))
                    if not res.ok:
                        return False
                except requests.ConnectionError as e:
                    print(e)
                    return False

        return True

    def close(self):
        super().close()
        thread_ids = list(self.HTTP_SESSION_POOL.keys())
        for thread_id in thread_ids:
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
    from pprint import pprint

    s = SolrStore(['127.0.0.1'])
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

    s.user.save('string', 'a')
    s.user.save('list', ['a', 'b', 1])
    s.user.save('int', 1)

    s.user.commit()

    print('\n# multiget string, list, int')
    pprint(s.user.multiget(['string', 'list', 'int']))

    print('\n# get sgaron')
    pprint(s.user.get('sgaron'))
    print('\n# get bob')
    pprint(s.user.get('bob'))

    print('\n# multiget sgaron, robert, denis')
    pprint(s.user.multiget(['sgaron', 'robert', 'denis']))

    print('\n# search *:*')
    pprint(s.user.search("*:*"))

    print('\n# search __expiry_ts__ all fields')
    pprint(s.user.search('__expiry_ts__:"2018-10-18T16:26:42.961Z+1DAY"', filters="__access_lvl__:100", fl="*"))

    print('\n# stream keys')
    for k in s.user.keys():
        print(k)

    print('\n# histogram number')
    pprint(s.user.histogram('__access_lvl__', 0, 1000, 100, mincount=2))

    print('\n# histogram date')
    pprint(s.user.histogram('__expiry_ts__', 'NOW-1MONTH/DAY', 'NOW+1DAY/DAY', '+1DAY'))

    print('\n# field analysis')
    pprint(s.user.field_analysis('__access_lvl__'))

    print('\n# grouped search')
    pprint(s.user.grouped_search(s.ID, rows=2, offset=1, sort='%s asc' % s.ID))
    pprint(s.user.grouped_search('__access_lvl__', rows=2, offset=1, sort='__access_lvl__ asc', fl=s.ID))

    print('\n# fields')
    pprint(s.user.fields())

    s.user.wipe()
    # print(s.user._search([('q', "*:*")]))
    # print(s.user._search([('q', "*:*"), ('fl', "*")]))
