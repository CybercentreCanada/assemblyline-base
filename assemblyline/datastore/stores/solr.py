import json
import threading

from copy import copy, deepcopy
from random import choice

from assemblyline.datastore import BaseStore, log, Collection, DataStoreException
from assemblyline.datastore.reconnect import collection_reconnect


requests = None


class SolrCollection(Collection):
    SOLR_GET_TIMEOUT_SEC = 5
    EXTRA_SEARCH_FIELD = '__text__'

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

    def _get_session(self):
        host_list = copy(self.datastore.hosts)
        session, host, url_path = self.datastore.get_or_create_session(host_list, None)
        if ":" not in host:
            host += ":8983"
        return session, host, url_path

    @collection_reconnect(log)
    def commit(self, host=None):
        if ":" not in host:
            host += ":8983"
        url = "http://{host}/{path}/{bucket}/update/?commit=true" \
              "&softCommit=true&wt=json".format(host=host, path=self.datastore.url_path, bucket=self.name)

        res = requests.get(url)
        if res.ok:
            solr_out = res.json()
            return solr_out
        else:
            return None

    @collection_reconnect(log)
    def get(self, key, strict=False):
        session, host, url_path = self._get_session()

        url = "http://{host}/{path}/{bucket}/get?id={key}&wt=json&fl=_source_".format(
            host=host, path=url_path, bucket=self.name, key=key)

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
        return None

    def _save(self, key, source_data):
        data = deepcopy(source_data)
        if not isinstance(data, dict):
            data = {"_source_": json.dumps(data)}
        else:
            data["_source_"] = json.dumps(data)
        data[self.datastore.ID] = key
        commit_within = int(self.COMMIT_WITHIN_MAP.get(self.name, None) or self.COMMIT_WITHIN_MAP["_default_"])

        session, host, url_path = self._get_session()
        url = "http://{host}/{path}/{bucket}/update/json" \
              "/docs?commitWithin={cw}&overwrite=true".format(host=host, path=url_path,
                                                              bucket=self.name, cw=commit_within)
        res = session.post(url, data=json.dumps(data), headers={"content-type": "application/json"})
        if not res.ok:
            try:
                raise DataStoreException(res.json())
            except Exception:
                raise DataStoreException(res.text)

    @collection_reconnect(log)
    def stream_keys(self, access_control=None):
        for item in self.datastore.stream_search(self.name, "*", fl=self.datastore.ID, access_control=access_control,
                                                 strict=False):
            yield item[self.datastore.ID]

    @collection_reconnect(log)
    def delete(self, key):
        data = {"delete": {"id": key}}
        commit_within = int(self.COMMIT_WITHIN_MAP.get(self.name, None) or self.COMMIT_WITHIN_MAP["_default_"])

        session, host, url_path = self._get_session()
        url = "http://{host}/{path}/{bucket}/update?commitWithin={cw}&overwrite=true".format(host=host,
                                                                                             path=url_path,
                                                                                             bucket=self.name,
                                                                                             cw=commit_within)
        res = session.post(url, data=json.dumps(data), headers={"content-type": "application/json"})
        return res.ok


class SolrStore(BaseStore):
    """ SOLR implementation of the ResultStore interface."""

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

    def __init__(self, hosts, filestore_factory):
        super(SolrStore, self).__init__(hosts, filestore_factory, SolrCollection)
        self.HTTP_SESSION_POOL = {}

    def __str__(self):
        return '{0} - {1}'.format(
            self.__class__.__name__,
            self._hosts)

    def close(self):
        super(SolrStore, self).close()
        for thread_id in self.HTTP_SESSION_POOL.keys():
            self._terminate_session(thread_id)

    def _terminate_session(self, thread_id):
        log.debug("Closing HTTP session for thread id: %s..." % thread_id)
        if thread_id in self.HTTP_SESSION_POOL:
            self.HTTP_SESSION_POOL[thread_id].close()
            del self.HTTP_SESSION_POOL[thread_id]

    def get_or_create_session(self, host_list, port):
        thread_id = threading.get_ident()
        host = choice(host_list)
        if port:
            port_addon = ":%s" % port
            host += port_addon
        session = self.HTTP_SESSION_POOL.get(thread_id, None)
        if not session:
            log.debug("Creating new HTTP session for %s..." % host)
            session = requests.Session()
            self.HTTP_SESSION_POOL[thread_id] = session

        return session, host, self.url_path

    # noinspection PyBroadException
    def connection_reset(self):
        # Kill the current session so it gets reconstructed
        self._terminate_session(threading.get_ident())
