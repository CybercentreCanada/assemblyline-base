import json
import os
import requests
import time
import threading

from copy import copy, deepcopy
from random import choice

from assemblyline.common.memory_zip import InMemoryZip
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

    @collection_reconnect(log)
    def keys(self, access_control=None):
        for item in self.datastore.stream_search(self.name, "*", fl=self.datastore.ID, access_control=access_control,
                                                 strict=False):
            yield item[self.datastore.ID]

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
        with requests.Session() as s:
            for host in self._hosts:
                try:
                    res = s.get('http://{host}/solr/admin/cores?action=STATUS'.format(host=host))
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
    print(s.user.get('sgaron'))
    print(s.user.multiget(['sgaron']))
