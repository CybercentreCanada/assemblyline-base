import json
import requests
import time
import threading

from copy import copy, deepcopy
from random import choice

from assemblyline.datastore import BaseStore, log, Collection, DataStoreException
from assemblyline.datastore.reconnect import collection_reconnect


class SolrCollection(Collection):
    SOLR_GET_TIMEOUT_SEC = 5
    MULTIGET_MAX_RETRY = 5
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

    ######################################
    # SOLR only methods
    def _get_session(self):
        session, host = self.datastore.get_or_create_session()
        if ":" not in host:
            host += ":8983"
        return session, host

    #####################################
    # Overloaded functions
    def __init__(self, datastore, name, model_class=None, api_base="solr"):
        self.api_base = api_base
        super().__init__(datastore, name, model_class=model_class)

    @collection_reconnect(log)
    def commit(self, host=None):
        for host in self.datastore.hosts:
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

            url = "http://{host}/{api_base}/{core}/get?id={keys}&wt=json&fl=_source_".format(
                host=host, api_base=self.api_base, core=self.name, keys=','.join(temp_keys))

            res = session.get(url, timeout=self.SOLR_GET_TIMEOUT_SEC)
            if res.ok:
                for doc in res.json().get('response', {}).get('docs', []):
                    if doc:
                        data = doc.get("_source_", None)
                        try:
                            data = json.loads(data)
                            if isinstance(data, dict):
                                data.pop(self.EXTRA_SEARCH_FIELD, None)
                            ret.append(data)
                        except ValueError:
                            ret.append(data)
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

        while retries != 0:
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

    @collection_reconnect(log)
    def keys(self, access_control=None):
        for item in self.datastore.stream_search(self.name, "*", fl=self.datastore.ID, access_control=access_control,
                                                 strict=False):
            yield item[self.datastore.ID]

    @collection_reconnect(log)
    def _ensure_index(self):
        # Test that the core exists and create it if it does not
        pass
        """
        http://localhost:8983/solr/admin/collections?action=LIST
        http://localhost:8983/solr/admin/collections?action=CREATE&name=test&numShards=1&replicationFactor=1
        
        """



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
    s.register('test')
    print(s.test.get('test'))
    s.test.save('test', 'test')
    print(s.test.get('test'))
