import json
import os
import requests
import time
import threading
import uuid

from copy import copy, deepcopy
from random import choice
from urllib.parse import quote

from assemblyline.common.chunk import chunked_list
from assemblyline.common.memory_zip import InMemoryZip
from assemblyline.common.str_utils import safe_str
from assemblyline.datastore import BaseStore, log, Collection, DataStoreException, SearchException, SearchRetryException
from assemblyline.datastore.support.solr.build import build_mapping, back_mapping


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

    DEFAULT_CATCH_ALL_FIELDS = """
    <dynamicField name="*_i"  type="pint"     indexed="true"  stored="true"/>
    <dynamicField name="*_is" type="pint"    indexed="true"  stored="true" multiValued="true"/>
    <dynamicField name="*_l"  type="plong"    indexed="true"  stored="true"/>
    <dynamicField name="*_ls" type="plong"   indexed="true"  stored="true" multiValued="true"/>
    <dynamicField name="*_d"  type="pdouble"  indexed="true"  stored="true"/>
    <dynamicField name="*_ds" type="pdouble" indexed="true"  stored="true" multiValued="true"/>
    <dynamicField name="*_f"  type="pfloat"   indexed="true"  stored="true"/>
    <dynamicField name="*_fs" type="pfloat"  indexed="true"  stored="true" multiValued="true"/>

    <dynamicField name="*_s"  type="string"   indexed="true"  stored="true"/>
    <dynamicField name="*_ss" type="string"  indexed="true"  stored="true" multiValued="true"/>

    <dynamicField name="*_t"  type="text" indexed="true"  stored="true"/>
    <dynamicField name="*_ts"  type="text" indexed="true"  stored="true" multiValued="true"/>

    <dynamicField name="*_b"   type="boolean"   indexed="true"  stored="true"/>
    <dynamicField name="*_bs"  type="boolean"  indexed="true"  stored="true" multiValued="true"/>
    <dynamicField name="*_dt"  type="pdate"     indexed="true"  stored="true"/>
    <dynamicField name="*_dts" type="pdate"    indexed="true"  stored="true" multiValued="true"/>
     """

    def __init__(self, datastore, name, model_class=None, api_base="solr", replication_factor=1, num_shards=1):
        self.api_base = api_base
        self.num_shards = replication_factor
        self.replication_factor = num_shards
        super().__init__(datastore, name, model_class=model_class)

        self.stored_fields = {}
        if model_class:
            for name, field in model_class.flat_fields().items():
                if field.store:
                    self.stored_fields[name] = field

    def with_retries(self, func, *args, **kwargs):
        retries = 0
        while True:
            try:
                return func(*args, **kwargs)
            except requests.RequestException:
                if retries < self.MAX_RETRY_BACKOFF:
                    time.sleep(retries)
                else:
                    time.sleep(self.MAX_RETRY_BACKOFF)
                self.datastore.connection_reset()
                retries += 1

    def _get_session(self, port=8983):
        session, host = self.datastore.get_or_create_session()
        if ":" not in host:
            host += ":%s" % port
        return session, host

    def commit(self):
        for host in self.datastore.get_hosts():
            if ":" not in host:
                host += ":8983"
            url = "http://{host}/{api_base}/{core}/update/?commit=true" \
                  "&softCommit=true&wt=json".format(host=host, api_base=self.api_base, core=self.name)

            res = requests.get(url)
            return res.ok

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

            res = self.with_retries(session.get, url, timeout=self.SOLR_GET_TIMEOUT_SEC)
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
                raise KeyError(str(temp_keys))

        return ret

    def _get(self, key, retries):
        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:
            session, host = self._get_session()

            url = "http://{host}/{api_base}/{core}/get?id={key}&wt=json&fl=_source_".format(
                host=host, api_base=self.api_base, core=self.name, key=key)

            res = self.with_retries(session.get, url, timeout=self.SOLR_GET_TIMEOUT_SEC)
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
        try:
            data = source_data.as_primitives()
        except AttributeError:
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
        res = self.with_retries(session.post, url, data=json.dumps(data), headers={"content-type": "application/json"})
        if not res.ok:
            try:
                raise DataStoreException(res.json())
            except Exception:
                raise DataStoreException(res.text)

        return True

    def delete(self, key):
        data = {"delete": {"id": key}}
        commit_within = int(self.COMMIT_WITHIN_MAP.get(self.name, None) or self.COMMIT_WITHIN_MAP["_default_"])

        session, host = self._get_session()
        url = "http://{host}/{api_base}/{core}/update?commitWithin={cw}&overwrite=true".format(host=host,
                                                                                               api_base=self.api_base,
                                                                                               core=self.name,
                                                                                               cw=commit_within)
        res = self.with_retries(session.post, url, data=json.dumps(data), headers={"content-type": "application/json"})
        return res.ok

    def delete_matching(self, query):
        data = {"delete": {"query": query}}
        commit_within = int(self.COMMIT_WITHIN_MAP.get(self.name, None) or self.COMMIT_WITHIN_MAP["_default_"])

        session, host = self._get_session()
        url = "http://{host}/{api_base}/{core}/update?commitWithin={cw}&overwrite=true".format(host=host,
                                                                                               api_base=self.api_base,
                                                                                               core=self.name,
                                                                                               cw=commit_within)
        res = self.with_retries(session.post, url, data=json.dumps(data), headers={"content-type": "application/json"})
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

    def _cleanup_search_result(self, item, fields=None):
        if self.model_class:
            item_id = item.pop(self.datastore.ID, None)
            if not fields or '*' in fields:
                fields = self.stored_fields.keys()
            elif isinstance(fields, str):
                fields = fields.split(',')

            item.pop('_version_', None)
            if '_source_' in item:
                data = json.loads(item['_source_'])
                return self.model_class(data, docid=item_id)
            return self.model_class(item, mask=fields, docid=item_id)

        if isinstance(item, dict):
            item.pop('_source_', None)
            item.pop('_version_', None)
            item.pop(self.EXTRA_SEARCH_FIELD, None)

        return {key: val if isinstance(val, list) else [val] for key, val in item.items()}

    # noinspection PyBroadException
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

        res = self.with_retries(session.get, url)
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
               fl=None, timeout=None, filters=None, access_control=None):

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
            "items": [self._cleanup_search_result(x, fl) for x in data['response']['docs']]
        }
        return output

    def stream_search(self, query, fl=None, filters=None, access_control=None, buffer_size=200):

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
                    _items.extend([self._cleanup_search_result(x, fl) for x in data['response']['docs']])

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

    def histogram(self, field, start, end, gap, query="*", mincount=1, filters=None, access_control=None):
        """Build a histogram of `query` data over `field`"""

        type_modifier = self._validate_steps_count(start, end, gap)

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
        return {type_modifier(x[0]): x[1]
                for x in chunked_list(result["facet_counts"]["facet_ranges"][field]["counts"], 2)}

    def field_analysis(self, field, query="*", prefix=None, contains=None, ignore_case=False, sort=None,
                       limit=10, min_count=1, filters=None, access_control=None):

        if not sort:
            sort = self.DEFAULT_SORT

        args = [
            ("q", query),
            ("rows", "0"),
            ("facet", "on"),
            ("facet.field", field),
            ("facet.limit", limit),
            ("facet.mincount", min_count),
            ("facet.missing", "false"),
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
        output = dict(chunked_list(result["facet_counts"]["facet_fields"][field], 2))
        output.pop("", None)
        return output

    def grouped_search(self, field, query="*", offset=0, sort=None, group_sort=None, fl=None, limit=1,
                       rows=None, filters=None, access_control=None):

        if not sort:
            sort = self.DEFAULT_SORT

        if not group_sort:
            group_sort = self.DEFAULT_SORT

        if not rows:
            rows = self.DEFAULT_ROW_SIZE

        args = [
            ("group", "on"),
            ("group.field", field),
            ('rows', rows),
            ('q', query),
            ('wt', 'json'),
            ('df', '__text__'),
            ("group.sort", group_sort),
            ("sort", sort),
            ("start", offset)
        ]

        if fl:
            args.append(('fl', fl))

        if limit:
            args.append(('group.limit', limit))

        if filters:
            if isinstance(filters, list):
                args.extend(('fq', ff) for ff in filters)
            else:
                args.append(('fq', filters))

        if access_control:
            args.append(('fq', access_control))

        args.append(('fq', "%s:[* TO *]" % field))

        data = self._search(args)['grouped'][field]

        return {
            'offset': offset,
            'rows': rows,
            'total': data['matches'],
            'items': [{
                'value': grouping['groupValue'],
                'total': grouping['doclist']['numFound'],
                'items': [self._cleanup_search_result(x, fl) for x in grouping['doclist']['docs']]
            } for grouping in data['groups']]
        }

    def _fields_from_schema(self, port=8983):
        session, host = self._get_session(port=port)

        url = f"http://{host}/{self.api_base}/{self.name}/schema/?wt=json"

        res = self.with_retries(session.get, url)
        if res.ok:
            collection_data = {}
            fields = res.json()['schema']['fields']
            for field in fields:
                field_name = field['name']
                if field_name.startswith("_") or "//" in field_name:
                    continue
                if not Collection.FIELD_SANITIZER.match(field_name):
                    continue

                collection_data[field_name] = {
                    "indexed": field['indexed'],
                    "stored": field['stored'],
                    "type": self._get_odm_type(field['type']),
                }

            return collection_data
        else:
            # noinspection PyBroadException
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

    @staticmethod
    def _get_odm_type(ds_type):
        try:
            return back_mapping[ds_type].__name__.lower()
        except KeyError:
            return ds_type.lower()

    def _field_from_data(self, port=8983):
        session, host = self._get_session(port=port)

        url = f"http://{host}/{self.api_base}/{self.name}/admin/luke?numTerms=0&wt=json"

        res = self.with_retries(session.get, url)
        if res.ok:
            collection_data = {}
            fields = res.json()['fields']
            for field_name, field in fields.items():
                if field_name.startswith("_") or "//" in field_name:
                    continue
                if not Collection.FIELD_SANITIZER.match(field_name):
                    continue

                collection_data[field_name] = {
                    "indexed": field.get("schema", "").startswith("I"),
                    "stored": field.get("schema", "")[:3].endswith("S"),
                    "type": self._get_odm_type(field['type']),
                }

            return collection_data
        else:
            # noinspection PyBroadException
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

    def fields(self, port=8983):
        fields = self._field_from_data(port=port)
        fields.update(self._fields_from_schema(port=port))
        return fields

    def _get_configset(self):
        schema = os.path.abspath(os.path.join(os.path.dirname(__file__), "../support/solr/managed-schema"))
        cfg = os.path.abspath(os.path.join(os.path.dirname(__file__), "../support/solr/solrconfig.xml"))

        # Read the schema file, insert the name and field list
        with open(schema) as fh:
            schema_raw = fh.read()

        schema_raw = schema_raw.replace('REPLACE_NAME', self.name.upper())

        if self.model_class:
            mapping = build_mapping(self.model_class.fields().values())
            schema_raw = schema_raw.replace('<!-- REPLACE_FIELDS -->', mapping)
        else:
            schema_raw = schema_raw.replace('<!-- REPLACE_FIELDS -->', self.DEFAULT_CATCH_ALL_FIELDS)

        # Read the config file, add the fields we want to receive by default
        with open(cfg, 'rb') as fh:
            cfg_raw = fh.read()

        if self.model_class:
            field_list = self.model_class.flat_fields()
            field_list = [name.encode() for name, field in field_list.items() if field.store]
            field_list.append(self.datastore.ID.encode())
            field_list = b','.join(field_list)
            cfg_raw = cfg_raw.replace(b'DEFAULT_FIELD_LIST', field_list)
        else:
            cfg_raw = cfg_raw.replace(b'DEFAULT_FIELD_LIST', b"*")

        # Zip up the combined configuration data
        zobj = InMemoryZip()
        zobj.append('managed-schema', schema_raw)
        zobj.append('solrconfig.xml', cfg_raw)
        return zobj.read()

    def _configset_exist(self, session=None, host=None):
        if session is None or host is None:
            session, host = self._get_session()

        test_url = "http://{host}/{api_base}/admin/configs?action=LIST".format(host=host, api_base=self.api_base)
        res = self.with_retries(session.get, test_url, headers={"content-type": "application/json"})
        if res.ok:
            data = res.json()
            log.info(f'config sets {data.get("configSets", [])}')
            if self.name not in data.get('configSets', []):
                return False
            return True
        else:
            raise DataStoreException("Cannot get to configset admin page.")

    def _ensure_configset(self, session=None, host=None):
        if session is None or host is None:
            session, host = self._get_session()

        if not self._configset_exist(session=session, host=host):
            log.info("ConfigSet {collection} does not exists. "
                     "Creating it now...".format(collection=self.name.upper()))
            upload_url = "http://{host}/{api_base}/admin/configs?action=UPLOAD" \
                         "&name={collection}".format(host=host, api_base=self.api_base, collection=self.name)
            res = self.with_retries(session.post, upload_url, data=self._get_configset(),
                                    headers={"content-type": "application/json"})
            if res.ok:
                log.info("Configset {collection} created!".format(collection=self.name))
            else:
                raise DataStoreException("Could not create configset {collection}.".format(collection=self.name))

    def _collection_exist(self, session=None, host=None):
        if session is None or host is None:
            session, host = self._get_session()

        test_url = "http://{host}/{api_base}/admin/collections?action=LIST".format(host=host, api_base=self.api_base)
        res = self.with_retries(session.get, test_url, headers={"content-type": "application/json"})
        if res.ok:
            data = res.json()
            log.info(f'collections {data.get("collections", [])}')
            if self.name not in data.get('collections', []):
                return False
            return True
        else:
            raise DataStoreException("Cannot get to collection admin page.")

    def _ensure_collection(self):
        session, host = self._get_session()

        # Make sure configset for collection exists
        self._ensure_configset(session=session, host=host)

        if not self._collection_exist(session=session, host=host):
            # Create collection
            log.warning(f"Collection {self.name.upper()} does not exists. "
                        "Creating it now...")
            create_url = f"http://{host}/{self.api_base}/admin/collections?action=CREATE" \
                f"&name={self.name}&numShards={self.num_shards}&replicationFactor={self.replication_factor}" \
                f"&collection.configName={self.name}"
            res = self.with_retries(session.get, create_url, headers={"content-type": "application/json"})

            if not res.ok:
                raise DataStoreException("Could not create collection {collection}.".format(collection=self.name))

            res = res.json()
            if 'failure' in res:
                raise DataStoreException(f"Could not create collection {self.name}. {res['failure']}")

            log.info("Collection {collection} created!".format(collection=self.name))

        self._check_fields()

    def wipe(self):
        log.warning("Wipe operation started for collection: %s" % self.name.upper())
        session, host = self._get_session()

        if self._collection_exist(session=session, host=host):
            log.warning("Removing collection: {collection}".format(collection=self.name.upper()))

            delete_url = "http://{host}/{api_base}/admin/collections?action=DELETE" \
                         "&name={collection}".format(host=host, api_base=self.api_base,
                                                     collection=self.name)
            res = self.with_retries(session.get, delete_url, headers={"content-type": "application/json"})
            if res.ok:
                log.warning("Collection {collection} deleted!".format(collection=self.name))
            else:
                raise DataStoreException("Could not create collection {collection}.".format(collection=self.name))

        if self._configset_exist(session=session, host=host):
            log.warning("Removing configset: {collection}".format(collection=self.name.upper()))
            delete_url = "http://{host}/{api_base}/admin/configs?action=DELETE" \
                         "&name={collection}".format(host=host, api_base=self.api_base, collection=self.name)
            res = self.with_retries(session.post, delete_url, data=self._get_configset(),
                                    headers={"content-type": "application/json"})
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
