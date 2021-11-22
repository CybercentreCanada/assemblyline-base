import json
import logging
import time
from copy import deepcopy
from os import environ
from random import random
from typing import Dict
from assemblyline.odm.base import BANNED_FIELDS

import elasticsearch
import elasticsearch.helpers

from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.dict_utils import recursive_update
from assemblyline.datastore import BaseStore, BulkPlan, Collection, log
from assemblyline.datastore.exceptions import (DataStoreException, ILMException, MultiKeyError, SearchException,
                                               SearchRetryException, VersionConflictException)
from assemblyline.datastore.support.elasticsearch.build import back_mapping, build_mapping
from assemblyline.datastore.support.elasticsearch.schemas import (default_dynamic_strings, default_dynamic_templates,
                                                                  default_index, default_mapping)

TRANSPORT_TIMEOUT = int(environ.get('AL_DATASTORE_TRANSPORT_TIMEOUT', '10'))
write_block_settings = {"settings": {"index.blocks.write": True}}
write_unblock_settings = {"settings": {"index.blocks.write": None}}

# A token value to represent a document not existing. Its a string to match the
# type used for version values. Any string will do as long as it never matches
# a real version string.
CREATE_TOKEN = 'create'


def _strip_lists(model, data):
    """Elasticsearch returns everything as lists, regardless of whether
    we want the field to be multi-valued or not. This method uses the model's
    knowlage of what should or should not have multiple values to fix the data.
    """
    fields = model.fields()
    out = {}
    for key, value in odm.flat_to_nested(data).items():
        doc_type = fields.get(key, fields.get('', model))
        # TODO: While we strip lists we don't want to know that the field is optional but we want to know what
        #       type of optional field that is. The following two lines of code change the doc_type to the
        #       child_type of the field. (Should model.fields() actually do that for us instead?)
        if isinstance(doc_type, odm.Optional):
            doc_type = doc_type.child_type

        if isinstance(doc_type, odm.List):
            out[key] = value
        elif isinstance(doc_type, odm.Compound) or isinstance(doc_type, odm.Mapping):
            out[key] = _strip_lists(doc_type.child_type, value)
        elif isinstance(value, list):
            out[key] = value[0]
        else:
            out[key] = value
    return out


def sort_str(sort_dicts):
    if sort_dicts is None:
        return sort_dicts

    sort_list = [f"{key}:{val}" for d in sort_dicts for key, val in d.items()]
    return ",".join(sort_list)


def parse_sort(sort, ret_list=True):
    """
    This function tries to do two things at once:
        - convert AL sort syntax to elastic,
        - convert any sorts on the key _id to _id_
    """
    if sort is None:
        return sort

    if isinstance(sort, list):
        return [parse_sort(row, ret_list=False) for row in sort]
    elif isinstance(sort, dict):
        return {('id' if key == '_id' else key): value for key, value in sort.items()}

    parts = sort.split(' ')
    if len(parts) == 1:
        if parts == '_id':
            if ret_list:
                return ['id']
            return 'id'
        if ret_list:
            return [parts]
        return parts
    elif len(parts) == 2:
        if parts[1] not in ['asc', 'desc']:
            raise SearchException('Unknown sort parameter ' + sort)
        if parts[0] == '_id':
            if ret_list:
                return [{'id': parts[1]}]
            return {'id': parts[1]}
        if ret_list:
            return [{parts[0]: parts[1]}]
        return {parts[0]: parts[1]}
    raise SearchException('Unknown sort parameter ' + sort)


class RetryableIterator(object):
    def __init__(self, collection, iterable):
        self._iter = iter(iterable)
        self.collection = collection

    def __iter__(self):
        return self

    def __next__(self):
        return self.collection.with_retries(self._iter.__next__)


class ElasticBulkPlan(BulkPlan):
    def __init__(self, indexes, model=None):
        super().__init__(indexes, model)

    def add_delete_operation(self, doc_id, index=None):
        if index:
            self.operations.append(json.dumps({"delete": {"_index": index, "_id": doc_id}}))
        else:
            for cur_index in self.indexes:
                self.operations.append(json.dumps({"delete": {"_index": cur_index, "_id": doc_id}}))

    def add_insert_operation(self, doc_id, doc, index=None):
        if isinstance(doc, self.model):
            saved_doc = doc.as_primitives(hidden_fields=True)
        elif self.model:
            saved_doc = self.model(doc).as_primitives(hidden_fields=True)
        else:
            if not isinstance(doc, dict):
                saved_doc = {'__non_doc_raw__': doc}
            else:
                saved_doc = deepcopy(doc)
        saved_doc['id'] = doc_id

        self.operations.append(json.dumps({"create": {"_index": index or self.indexes[0], "_id": doc_id}}))
        self.operations.append(json.dumps(saved_doc))

    def add_upsert_operation(self, doc_id, doc, index=None):
        if isinstance(doc, self.model):
            saved_doc = doc.as_primitives(hidden_fields=True)
        elif self.model:
            saved_doc = self.model(doc).as_primitives(hidden_fields=True)
        else:
            if not isinstance(doc, dict):
                saved_doc = {'__non_doc_raw__': doc}
            else:
                saved_doc = deepcopy(doc)
        saved_doc['id'] = doc_id

        self.operations.append(json.dumps({"update": {"_index": index or self.indexes[0], "_id": doc_id}}))
        self.operations.append(json.dumps({"doc": saved_doc, "doc_as_upsert": True}))

    def add_update_operation(self, doc_id, doc, index=None):

        if isinstance(doc, self.model):
            saved_doc = doc.as_primitives(hidden_fields=True)
        elif self.model:
            saved_doc = self.model(doc, mask=list(doc.keys())).as_primitives(hidden_fields=True)
        else:
            if not isinstance(doc, dict):
                saved_doc = {'__non_doc_raw__': doc}
            else:
                saved_doc = deepcopy(doc)

        if index:
            self.operations.append(json.dumps({"update": {"_index": index, "_id": doc_id}}))
            self.operations.append(json.dumps({"doc": saved_doc}))
        else:
            for cur_index in self.indexes:
                self.operations.append(json.dumps({"update": {"_index": cur_index, "_id": doc_id}}))
                self.operations.append(json.dumps({"doc": saved_doc}))

    def get_plan_data(self):
        return "\n".join(self.operations)


class ESCollection(Collection):
    DEFAULT_SORT = [{'_id': 'asc'}]
    MAX_SEARCH_ROWS = 500
    MAX_GROUP_LIMIT = 10
    MAX_FACET_LIMIT = 100
    SCROLL_TIMEOUT = "5m"
    DEFAULT_SEARCH_VALUES = {
        'timeout': None,
        'field_list': None,
        'facet_active': False,
        'facet_mincount': 1,
        'facet_fields': [],
        'stats_active': False,
        'stats_fields': [],
        'filters': [],
        'group_active': False,
        'group_field': None,
        'group_sort': None,
        'group_limit': 1,
        'histogram_active': False,
        'histogram_field': None,
        'histogram_type': None,
        'histogram_gap': None,
        'histogram_mincount': 1,
        'histogram_start': None,
        'histogram_end': None,
        'start': 0,
        'rows': Collection.DEFAULT_ROW_SIZE,
        'query': "*",
        'sort': DEFAULT_SORT,
        'df': None,
        'script_fields': []
    }

    def __init__(self, datastore, name, model_class=None, validate=True):
        self.replicas = environ.get(f"ELASTIC_{name.upper()}_REPLICAS", environ.get('ELASTIC_DEFAULT_REPLICAS', 0))
        self.shards = environ.get(f"ELASTIC_{name.upper()}_SHARDS", environ.get('ELASTIC_DEFAULT_SHARDS', 1))
        self._index_list = []

        if name in datastore.ilm_config:
            self.ilm_config = datastore.ilm_config[name]
        else:
            self.ilm_config = None

        super().__init__(datastore, name, model_class=model_class, validate=validate)

        self.bulk_plan_class = ElasticBulkPlan
        self.stored_fields = {}
        if model_class:
            for name, field in model_class.flat_fields().items():
                if field.store:
                    self.stored_fields[name] = field

    @property
    def archive_access(self):
        if self.ilm_config and self.datastore.archive_access:
            return True
        return False

    @property
    def index_list_full(self):
        if not self._index_list:
            self._index_list = list(self.with_retries(self.datastore.client.indices.get, f"{self.name}-*").keys())

        return [self.index_name] + sorted(self._index_list, reverse=True)

    @property
    def index_list(self):
        if self.archive_access:
            if not self._index_list:
                self._index_list = list(self.with_retries(self.datastore.client.indices.get, f"{self.name}-*").keys())

            return [self.index_name] + sorted(self._index_list, reverse=True)
        else:
            return [self.index_name]

    def with_retries(self, func, *args, raise_conflicts=False, **kwargs):
        retries = 0
        updated = 0
        deleted = 0
        while True:
            try:
                ret_val = func(*args, **kwargs)

                if retries:
                    log.info('Reconnected to elasticsearch!')

                if updated:
                    ret_val['updated'] += updated

                if deleted:
                    ret_val['deleted'] += deleted

                return ret_val

            except elasticsearch.exceptions.NotFoundError as e:
                if "index_not_found_exception" in str(e):
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    log.debug("The index does not exist. Trying to recreate it...")
                    self._ensure_collection()
                    self.datastore.connection_reset()
                    retries += 1
                else:
                    raise

            except elasticsearch.exceptions.ConflictError as ce:
                if raise_conflicts:
                    # De-sync potential treads trying to write to the index
                    time.sleep(random() * 0.1)
                    raise VersionConflictException(str(ce))
                updated += ce.info.get('updated', 0)
                deleted += ce.info.get('deleted', 0)

                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.datastore.connection_reset()
                retries += 1

            except elasticsearch.exceptions.ConnectionTimeout:
                log.warning(f"Elasticsearch connection timeout, server(s): "
                            f"{' | '.join(self.datastore.get_hosts(safe=True))}"
                            f", retrying {func.__name__}...")
                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.datastore.connection_reset()
                retries += 1

            except (SearchRetryException,
                    elasticsearch.exceptions.ConnectionError,
                    elasticsearch.exceptions.AuthenticationException) as e:
                if not isinstance(e, SearchRetryException):
                    log.warning(f"No connection to Elasticsearch server(s): "
                                f"{' | '.join(self.datastore.get_hosts(safe=True))}"
                                f", because [{e}] retrying {func.__name__}...")

                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.datastore.connection_reset()
                retries += 1

            except elasticsearch.exceptions.TransportError as e:
                err_code, msg, cause = e.args
                if err_code == 503 or err_code == '503':
                    log.warning(f"Looks like index {self.name} is not ready yet, retrying...")
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    self.datastore.connection_reset()
                    retries += 1
                elif err_code == 429 or err_code == '429':
                    log.warning("Elasticsearch is too busy to perform the requested "
                                f"task on index {self.name}, retrying...")
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    self.datastore.connection_reset()
                    retries += 1
                elif err_code == 403 or err_code == '403':
                    log.warning("Elasticsearch cluster is preventing writing operations "
                                f"on index {self.name}, retrying...")
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    self.datastore.connection_reset()
                    retries += 1

                else:
                    raise

    def _get_task_results(self, task):
        # This function is only used to wait for a asynchronous task to finish in a graceful manner without
        #  timing out the elastic client. You can create an async task for long running operation like:
        #   - update_by_query
        #   - delete_by_query
        #   - reindex ...
        res = None
        while res is None:
            try:
                res = self.with_retries(self.datastore.client.tasks.get, task['task'],
                                        wait_for_completion=True, timeout='5s')
            except elasticsearch.exceptions.TransportError as e:
                err_code, msg, _ = e.args
                if (err_code == 500 or err_code == '500') and msg == 'timeout_exception':
                    pass
                else:
                    raise

        try:
            return res['response']
        except KeyError:
            return res['task']['status']

    def _safe_index_copy(self, copy_function, src, target, body=None, min_status='yellow'):
        ret = copy_function(src, target, body=body, request_timeout=60)
        if not ret['acknowledged']:
            raise DataStoreException(f"Failed to create index {target} from {src}.")

        status_ok = False
        while not status_ok:
            try:
                res = self.datastore.client.cluster.health(index=target, timeout='5s', wait_for_status=min_status)
                status_ok = not res['timed_out']
            except elasticsearch.exceptions.TransportError as e:
                err_code, _, _ = e.args
                if err_code == 408 or err_code == '408':
                    log.warning(f"Waiting for index {target} to get to status {min_status}...")
                    pass
                else:
                    raise

    def _delete_async(self, index, body, max_docs=None, sort=None):
        deleted = 0
        while True:
            task = self.with_retries(self.datastore.client.delete_by_query, index=index,
                                     body=body, wait_for_completion=False, conflicts='proceed',
                                     sort=sort, max_docs=max_docs)
            res = self._get_task_results(task)

            if res['version_conflicts'] == 0:
                res['deleted'] += deleted
                return res
            else:
                deleted += res['deleted']

    def _update_async(self, index, body, max_docs=None):
        updated = 0
        while True:
            task = self.with_retries(self.datastore.client.update_by_query, index=index,
                                     body=body, wait_for_completion=False, conflicts='proceed', max_docs=max_docs)
            res = self._get_task_results(task)

            if res['version_conflicts'] == 0:
                res['updated'] += updated
                return res
            else:
                updated += res['updated']

    def archive(self, query, max_docs=None, sort=None):
        if not self.archive_access:
            return False

        reindex_body = {
            "source": {
                "index": self.index_name,
                "query": {
                    "bool": {
                        "must": {
                            "query_string": {
                                "query": query
                            }
                        }
                    }
                }
            },
            "dest": {
                "index": f"{self.name}-archive"
            }
        }
        if max_docs:
            reindex_body['source']['size'] = max_docs

        if sort:
            reindex_body['source']['sort'] = parse_sort(sort)

        r_task = self.with_retries(self.datastore.client.reindex, reindex_body, wait_for_completion=False)
        res = self._get_task_results(r_task)
        total_archived = res['updated'] + res['created']
        if res['total'] == total_archived or max_docs == total_archived:
            if total_archived != 0:
                delete_body = {"query": {"bool": {"must": {"query_string": {"query": query}}}}}
                info = self._delete_async(self.name, delete_body, max_docs=max_docs, sort=sort_str(parse_sort(sort)))
                return info.get('deleted', 0) == total_archived
            else:
                return True
        else:
            return False

    def _bulk(self, operations):
        return self.with_retries(self.datastore.client.bulk, body=operations)

    def commit(self):
        self.with_retries(self.datastore.client.indices.refresh, self.index_name)
        self.with_retries(self.datastore.client.indices.clear_cache, self.index_name)
        if self.archive_access:
            self.with_retries(self.datastore.client.indices.refresh, f"{self.name}-archive")
            self.with_retries(self.datastore.client.indices.clear_cache, f"{self.name}-archive")
        return True

    def fix_ilm(self):
        if self.ilm_config:
            # Create ILM policy
            while not self._ilm_policy_exists():
                try:
                    self.with_retries(self._create_ilm_policy)
                except ILMException:
                    time.sleep(0.1)
                    pass

            # Create WARM index template
            if not self.with_retries(self.datastore.client.indices.exists_template, self.name):
                log.debug(f"Index template {self.name.upper()} does not exists. Creating it now...")

                index = self._get_index_definition()

                index["index_patterns"] = [f"{self.name}-*"]
                index["order"] = 1
                index["settings"]["index.lifecycle.name"] = f"{self.name}_policy"
                index["settings"]["index.lifecycle.rollover_alias"] = f"{self.name}-archive"

                try:
                    self.with_retries(self.datastore.client.indices.put_template, self.name, index)
                except elasticsearch.exceptions.RequestError as e:
                    if "resource_already_exists_exception" not in str(e):
                        raise
                    log.warning(f"Tried to create an index template that already exists: {self.name.upper()}")

            if not self.with_retries(self.datastore.client.indices.exists_alias, f"{self.name}-archive"):
                log.debug(f"Index alias {self.name.upper()}-archive does not exists. Creating it now...")

                index = {"aliases": {f"{self.name}-archive": {"is_write_index": True}}}

                try:
                    self.with_retries(self.datastore.client.indices.create, f"{self.name}-000001", index)
                except elasticsearch.exceptions.RequestError as e:
                    if "resource_already_exists_exception" not in str(e):
                        raise
                    log.warning(f"Tried to create an index template that already exists: {self.name.upper()}-000001")
        else:
            for idx in self.index_list_full:
                if idx != self.index_name:
                    body = {
                        "source": {
                            "index": idx
                        },
                        "dest": {
                            "index": self.index_name
                        }
                    }

                    r_task = self.with_retries(self.datastore.client.reindex, body, wait_for_completion=False)
                    self._get_task_results(r_task)

                    self.with_retries(self.datastore.client.indices.refresh, self.index_name)
                    self.with_retries(self.datastore.client.indices.clear_cache, self.index_name)

                    self.with_retries(self.datastore.client.indices.delete, idx)

            if self._ilm_policy_exists():
                self.with_retries(self._delete_ilm_policy)

            if self.with_retries(self.datastore.client.indices.exists_template, self.name):
                self.with_retries(self.datastore.client.indices.delete_template, self.name)

        return True

    def fix_replicas(self):
        replicas = self._get_index_definition()['settings']['index']['number_of_replicas']
        body = {"number_of_replicas": replicas}
        return self.with_retries(
            self.datastore.client.indices.put_settings, index=self.index_name, body=body)['acknowledged']

    def fix_shards(self):
        body = {"settings": self._get_index_definition()['settings']}
        clone_body = {"settings": {"index.number_of_replicas": 0}}
        method = None
        temp_name = f'{self.name}__fix_shards'

        indexes_settings = self.with_retries(self.datastore.client.indices.get_settings)
        current_settings = indexes_settings.get(self.index_name, indexes_settings.get(temp_name, None))
        if not current_settings:
            raise DataStoreException(
                'Could not get current index settings. Something is wrong and requires manual intervention...')

        cur_replicas = int(current_settings['settings']['index']['number_of_replicas'])
        cur_shards = int(current_settings['settings']['index']['number_of_shards'])
        target_shards = int(body['settings']['index']['number_of_shards'])

        if cur_shards > target_shards:
            target_node = self.with_retries(self.datastore.client.cat.nodes, format='json')[0]['name']
            clone_setup_settings = {"settings": {"index.number_of_replicas": 0,
                                                 "index.routing.allocation.require._name": target_node}}
            clone_finish_settings = {"settings": {"index.number_of_replicas": cur_replicas,
                                                  "index.routing.allocation.require._name": None}}
            method = self.datastore.client.indices.shrink
        elif cur_shards < target_shards:
            method = self.datastore.client.indices.split
            clone_setup_settings = None
            clone_finish_settings = None

        if method:
            try:
                # Block write to the index
                self.with_retries(self.datastore.client.indices.put_settings, body=write_block_settings)

                # Clone it onto a temporary index
                if not self.with_retries(self.datastore.client.indices.exists, temp_name):
                    # if there are specific settings to be applied to the index, apply them
                    if clone_setup_settings:
                        self.with_retries(self.datastore.client.indices.put_settings,
                                          index=self.index_name, body=clone_setup_settings)

                        # Make sure no shard are relocating
                        while self.datastore.client.cluster.health(index=self.index_name)['relocating_shards'] != 0:
                            time.sleep(1)

                    self._safe_index_copy(self.datastore.client.indices.clone,
                                          self.index_name, temp_name, body=clone_body)

                    # Make the hot index the new clone
                    alias_body = {"actions": [{"add":  {"index": temp_name, "alias": self.name}}, {
                        "remove_index": {"index": self.index_name}}]}
                    self.with_retries(self.datastore.client.indices.update_aliases, alias_body)

                if self.with_retries(self.datastore.client.indices.exists, self.index_name):
                    self.with_retries(self.datastore.client.indices.delete, self.index_name)

                # Shrink index into shrinked_name
                self._safe_index_copy(method, temp_name, self.index_name, body=body)

                # Make the hot index the new clone
                alias_body = {"actions": [{"add":  {"index": self.index_name, "alias": self.name}}, {
                    "remove_index": {"index": temp_name}}]}
                self.with_retries(self.datastore.client.indices.update_aliases, alias_body)
            finally:
                # Restore writes
                self.with_retries(self.datastore.client.indices.put_settings, body=write_unblock_settings)

                # if there are specific settings to be applied to the index, apply them
                if clone_finish_settings:
                    self.with_retries(self.datastore.client.indices.put_settings,
                                      index=self.index_name, body=clone_finish_settings)

    def reindex(self):
        for index in self.index_list:
            new_name = f'{index}__reindex'
            if self.with_retries(self.datastore.client.indices.exists, index) and \
                    not self.with_retries(self.datastore.client.indices.exists, new_name):

                # Get information about the index to reindex
                index_data = self.with_retries(self.datastore.client.indices.get, index)[index]

                # Create reindex target
                self.with_retries(self.datastore.client.indices.create, new_name, self._get_index_definition())

                # For all aliases related to the index, add a new alias to the reindex index
                for alias, alias_data in index_data['aliases'].items():
                    # Make the reindex index the new write index if the original index was
                    if alias_data.get('is_write_index', True):
                        alias_body = {"actions": [
                            {"add": {"index": new_name, "alias": alias, "is_write_index": True}},
                            {"add": {"index": index, "alias": alias, "is_write_index": False}}, ]}
                    else:
                        alias_body = {"actions": [
                            {"add": {"index": new_name, "alias": alias}}]}
                    self.with_retries(self.datastore.client.indices.update_aliases, alias_body)

                # Reindex data into target
                body = {
                    "source": {
                        "index": index
                    },
                    "dest": {
                        "index": new_name
                    }
                }
                r_task = self.with_retries(self.datastore.client.reindex, body, wait_for_completion=False)
                self._get_task_results(r_task)

                # Commit reindexed data
                self.with_retries(self.datastore.client.indices.refresh, new_name)
                self.with_retries(self.datastore.client.indices.clear_cache, new_name)

                # Delete old index
                self.with_retries(self.datastore.client.indices.delete, index)

                # Block write to the index
                self.with_retries(self.datastore.client.indices.put_settings, body=write_block_settings)

                # Rename reindexed index
                try:
                    clone_body = {"settings": self._get_index_definition()['settings']}
                    self._safe_index_copy(self.datastore.client.indices.clone, new_name, index, body=clone_body)

                    # Restore original aliases for the index
                    for alias, alias_data in index_data['aliases'].items():
                        # Make the reindex index the new write index if the original index was
                        if alias_data.get('is_write_index', True):
                            alias_body = {"actions": [
                                {"add": {"index": index, "alias": alias, "is_write_index": True}},
                                {"remove_index": {"index": new_name}}]}
                            self.with_retries(self.datastore.client.indices.update_aliases, alias_body)

                    # Delete the reindex target if it still exists
                    if self.with_retries(self.datastore.client.indices.exists, new_name):
                        self.with_retries(self.datastore.client.indices.delete, new_name)
                finally:
                    # Unblock write to the index
                    self.with_retries(self.datastore.client.indices.put_settings, body=write_unblock_settings)

        return True

    def multiget(self, key_list, as_dictionary=True, as_obj=True, error_on_missing=True):

        def add_to_output(data_output, data_id):
            if "__non_doc_raw__" in data_output:
                if as_dictionary:
                    out[data_id] = data_output['__non_doc_raw__']
                else:
                    out.append(data_output['__non_doc_raw__'])
            else:
                data_output.pop('id', None)
                if as_dictionary:
                    out[data_id] = self.normalize(data_output, as_obj=as_obj)
                else:
                    out.append(self.normalize(data_output, as_obj=as_obj))

        if as_dictionary:
            out = {}
        else:
            out = []

        if key_list:
            data = self.with_retries(self.datastore.client.mget, {'ids': key_list}, index=self.name)

            for row in data.get('docs', []):
                if 'found' in row and not row['found']:
                    continue

                try:
                    key_list.remove(row['_id'])
                    add_to_output(row['_source'], row['_id'])
                except ValueError:
                    log.error(f'MGet returned multiple documents for id: {row["_id"]}')

            if key_list and self.archive_access:
                query_body = {"query": {"ids": {"values": key_list}}}
                iterator = RetryableIterator(
                    self,
                    elasticsearch.helpers.scan(
                        self.datastore.client,
                        query=query_body,
                        index=f"{self.name}-*",
                        preserve_order=True
                    )
                )

                for row in iterator:
                    try:
                        key_list.remove(row['_id'])
                        add_to_output(row['_source'], row['_id'])
                    except ValueError:
                        log.error(f'MGet returned multiple documents for id: {row["_id"]}')

        if key_list and error_on_missing:
            raise MultiKeyError(key_list, out)

        return out

    def exists(self, key, force_archive_access=False):
        found = self.with_retries(self.datastore.client.exists, index=self.name, id=key, _source=False)

        if not found and (self.archive_access or (self.ilm_config and force_archive_access)):
            query_body = {"query": {"ids": {"values": [key]}}, "size": 0}
            res = self.with_retries(self.datastore.client.search, index=f"{self.name}-*",
                                    body=query_body)
            found = res['hits']['total']['value'] > 0

        return found

    def _get(self, key, retries, force_archive_access=False, version=False):
        """

        Versioned get-save for atomic update has three paths:
            1. Document doesn't exist at all. Create token will be returned for version.
               This way only the first query to try and create the document will succeed.
            2. Document exists in archive. Create token will be returned for version.
               This way only the first query to try and 'move' the value from archive to hot will succeed.
            3. Document exists in hot. A version string with the info needed to do a versioned save is returned.

        The create token is needed to differentiate between "I'm saving a new
        document non-atomic (version=None)" and "I'm saving a new document
        atomically (version=CREATE_TOKEN)".

        """

        def normalize_output(data_output):
            if "__non_doc_raw__" in data_output:
                return data_output['__non_doc_raw__']
            data_output.pop('id', None)
            return data_output

        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:
            try:
                doc = self.with_retries(self.datastore.client.get, index=self.name, id=key)
                if version:
                    return normalize_output(doc['_source']), f"{doc['_seq_no']}---{doc['_primary_term']}"
                return normalize_output(doc['_source'])
            except elasticsearch.exceptions.NotFoundError:
                pass

            if self.archive_access or (self.ilm_config and force_archive_access):
                query_body = {"query": {"ids": {"values": [key]}}, 'size': 1, 'sort': {'_index': 'desc'}}
                hits = self.with_retries(self.datastore.client.search, index=f"{self.name}-*",
                                         body=query_body)['hits']['hits']
                if len(hits) > 0:
                    if version:
                        return normalize_output(hits[0]['_source']), CREATE_TOKEN
                    return normalize_output(hits[0]['_source'])

            if retries > 0:
                time.sleep(0.05)
                retries -= 1
            elif retries < 0:
                time.sleep(0.05)
            else:
                done = True

        if version:
            return None, CREATE_TOKEN
        return None

    def _save(self, key, data, version=None):
        if self.model_class:
            saved_data = data.as_primitives(hidden_fields=True)
        else:
            if not isinstance(data, dict):
                saved_data = {'__non_doc_raw__': data}
            else:
                saved_data = deepcopy(data)

        saved_data['id'] = key
        operation = 'index'
        seq_no = None
        primary_term = None

        if version == CREATE_TOKEN:
            operation = 'create'
        elif version:
            seq_no, primary_term = version.split('---')

        self.with_retries(
            self.datastore.client.index,
            index=self.name,
            id=key,
            body=json.dumps(saved_data),
            op_type=operation,
            if_seq_no=seq_no,
            if_primary_term=primary_term,
            raise_conflicts=True
        )

        return True

    def delete(self, key):
        deleted = False
        try:
            info = self.with_retries(self.datastore.client.delete, id=key, index=self.name)
            deleted = info['result'] == 'deleted'
        except elasticsearch.NotFoundError:
            pass

        if self.archive_access:
            query_body = {"query": {"ids": {"values": [key]}}}
            info = self._delete_async(f"{self.name}-*", query_body)
            if not deleted:
                deleted = info.get('deleted', 0) == info.get('total', 0)
        else:
            deleted = True

        return deleted

    def delete_by_query(self, query, workers=20, sort=None, max_docs=None):
        index = self.name
        if self.archive_access:
            index = f"{index},{self.name}-*"
        query_body = {"query": {"bool": {"must": {"query_string": {"query": query}}}}}
        info = self._delete_async(index, query_body, sort=sort_str(parse_sort(sort)), max_docs=max_docs)
        return info.get('deleted', 0) != 0

    def _create_scripts_from_operations(self, operations):
        op_sources = []
        op_params = {}
        val_id = 0
        for op, doc_key, value in operations:
            if op == self.UPDATE_SET:
                op_sources.append(f"ctx._source.{doc_key} = params.value{val_id}")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_DELETE:
                op_sources.append(f"ctx._source.{doc_key}.remove(params.value{val_id})")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_APPEND:
                op_sources.append(f"ctx._source.{doc_key}.add(params.value{val_id})")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_REMOVE:
                script = f"if (ctx._source.{doc_key}.indexOf(params.value{val_id}) != -1) " \
                         f"{{ctx._source.{doc_key}.remove(ctx._source.{doc_key}.indexOf(params.value{val_id}))}}"
                op_sources.append(script)
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_INC:
                op_sources.append(f"ctx._source.{doc_key} += params.value{val_id}")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_DEC:
                op_sources.append(f"ctx._source.{doc_key} -= params.value{val_id}")
                op_params[f'value{val_id}'] = value

            val_id += 1

        joined_sources = """;\n""".join(op_sources)

        script = {
            "lang": "painless",
            "source": joined_sources.replace("};\n", "}\n"),
            "params": op_params
        }
        return script

    def _update(self, key, operations):
        script = self._create_scripts_from_operations(operations)

        update_body = {
            "script": script
        }

        # noinspection PyBroadException
        try:
            res = self.with_retries(self.datastore.client.update, index=self.name, id=key, body=update_body)
            return res['result'] == "updated"
        except elasticsearch.NotFoundError:
            pass
        except Exception:
            return False

        if self.archive_access:
            query_body = {"query": {"ids": {"values": [key]}}}
            update_body.update(query_body)
            info = self._update_async(f"{self.name}-*", update_body)
            return info.get('updated', 0) != 0

        return False

    def _update_by_query(self, query, operations, filters, max_docs=None):
        if filters is None:
            filters = []

        index = self.name
        if self.archive_access:
            index = f"{index},{self.name}-*"

        script = self._create_scripts_from_operations(operations)

        query_body = {
            "script": script,
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": query
                        }
                    },
                    'filter': [{'query_string': {'query': ff}} for ff in filters]
                }
            }
        }

        # noinspection PyBroadException
        try:
            res = self._update_async(index, query_body, max_docs=max_docs)
        except Exception:
            return False

        return res['updated']

    def _format_output(self, result, fields=None, as_obj=True):
        # Getting search document data
        extra_fields = result.get('fields', {})
        source_data = result.pop('_source', None)
        for f in BANNED_FIELDS:
            source_data.pop(f, None)
        item_id = result['_id']

        if self.model_class:
            if not fields:
                fields = list(self.stored_fields.keys())
                fields.append('id')
            elif isinstance(fields, str):
                fields = fields.split(',')

            extra_fields = _strip_lists(self.model_class, extra_fields)
            if as_obj:
                if '_index' in fields and '_index' in result:
                    extra_fields['_index'] = result["_index"]
                if '*' in fields:
                    fields = None
                return self.model_class(source_data, mask=fields, docid=item_id, extra_fields=extra_fields)
            else:
                source_data = recursive_update(source_data, extra_fields)
                if 'id' in fields:
                    source_data['id'] = item_id
                if '_index' in fields and '_index' in result:
                    source_data['_index'] = result["_index"]
                return source_data

        if isinstance(fields, str):
            fields = fields

        if fields is None or '*' in fields or 'id' in fields:
            source_data['id'] = [item_id]

        if fields is None or '*' in fields:
            return source_data

        return {key: val for key, val in source_data.items() if key in fields}

    def _search(self, args=None, deep_paging_id=None, use_archive=False, track_total_hits=None):
        index = self.name
        if self.archive_access and use_archive:
            index = f"{index},{self.name}-*"

        params = {}
        if deep_paging_id is not None:
            params = {'scroll': self.SCROLL_TIMEOUT}
        elif track_total_hits:
            params['track_total_hits'] = track_total_hits

        parsed_values = deepcopy(self.DEFAULT_SEARCH_VALUES)

        # TODO: we should validate values for max rows, group length, history length...
        for key, value in args:
            if key not in parsed_values:
                all_args = '; '.join('%s=%s' % (field_name, field_value) for field_name, field_value in args)
                raise ValueError("Unknown query argument: %s %s of [%s]" % (key, value, all_args))

            parsed_values[key] = value

        # This is our minimal query, the following sections will fill it out
        # with whatever extra options the search has been given.
        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": parsed_values['query']
                        }
                    },
                    'filter': [{'query_string': {'query': ff}} for ff in parsed_values['filters']]
                }
            },
            'from': parsed_values['start'],
            'size': parsed_values['rows'],
            'sort': parse_sort(parsed_values['sort']),
            "_source": parsed_values['field_list'] or list(self.stored_fields.keys())
        }

        if parsed_values['script_fields']:
            fields = {}
            for (f_name, f_script) in parsed_values['script_fields']:
                fields[f_name] = {
                    "script": {
                        "lang": "painless",
                        "source": f_script
                    }
                }
            query_body["script_fields"] = fields

        if parsed_values['df']:
            query_body["query"]["bool"]["must"]["query_string"]["default_field"] = parsed_values['df']

        # Time limit for the query
        if parsed_values['timeout']:
            query_body['timeout'] = parsed_values['timeout']

        # Add an histogram aggregation
        if parsed_values['histogram_active']:
            query_body["aggregations"] = query_body.get("aggregations", {})
            if parsed_values['histogram_type'] == "date_histogram":
                interval_type = "calendar_interval"
            else:
                interval_type = "interval"
            query_body["aggregations"]["histogram"] = {
                parsed_values['histogram_type']: {
                    "field": parsed_values['histogram_field'],
                    interval_type: parsed_values['histogram_gap'],
                    "min_doc_count": parsed_values['histogram_mincount'],
                    "extended_bounds": {
                        "min": parsed_values['histogram_start'],
                        "max": parsed_values['histogram_end']
                    }
                }
            }

        # Add a facet aggregation
        if parsed_values['facet_active']:
            query_body["aggregations"] = query_body.get("aggregations", {})
            for field in parsed_values['facet_fields']:
                query_body["aggregations"][field] = {
                    "terms": {
                        "field": field,
                        "min_doc_count": parsed_values['facet_mincount']
                    }
                }

        # Add a facet aggregation
        if parsed_values['stats_active']:
            query_body["aggregations"] = query_body.get("aggregations", {})
            for field in parsed_values['stats_fields']:
                query_body["aggregations"][f"{field}_stats"] = {
                    "stats": {
                        "field": field
                    }
                }

        # Add a group aggregation
        if parsed_values['group_active']:
            query_body["collapse"] = {
                "field": parsed_values['group_field'],
                "inner_hits": {
                    "name": "group",
                    "_source": parsed_values['field_list'] or list(self.stored_fields.keys()),
                    "size": parsed_values['group_limit'],
                    "sort": parse_sort(parsed_values['group_sort']) or [{parsed_values['group_field']: 'asc'}]
                }
            }

        try:
            if deep_paging_id is not None and not deep_paging_id == "*":
                # Get the next page
                result = self.with_retries(self.datastore.client.scroll, scroll_id=deep_paging_id, params=params)
            else:
                # Run the query
                result = self.with_retries(self.datastore.client.search, index=index,
                                           body=json.dumps(query_body), params=params)

            return result

        except (elasticsearch.TransportError, elasticsearch.RequestError) as e:
            try:
                err_msg = e.info['error']['root_cause'][0]['reason']
            except (ValueError, KeyError, IndexError):
                err_msg = str(e)
            raise SearchException(err_msg)

        except (elasticsearch.ConnectionError, elasticsearch.ConnectionTimeout) as error:
            raise SearchRetryException("collection: %s, query: %s, error: %s" % (self.name, query_body, str(error)))

        except Exception as error:
            raise SearchException("collection: %s, query: %s, error: %s" % (self.name, query_body, str(error)))

    def search(self, query, offset=0, rows=None, sort=None,
               fl=None, timeout=None, filters=None, access_control=None,
               deep_paging_id=None, as_obj=True, use_archive=False, track_total_hits=None, script_fields=[]):

        if rows is None:
            rows = self.DEFAULT_ROW_SIZE

        if sort is None:
            sort = self.DEFAULT_SORT

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        if access_control:
            filters.append(access_control)

        args = [
            ('query', query),
            ('start', offset),
            ('rows', rows),
            ('sort', sort),
            ('df', self.DEFAULT_SEARCH_FIELD)
        ]

        if fl:
            field_list = fl.split(',')
            args.append(('field_list', field_list))
        else:
            field_list = None

        if timeout:
            args.append(('timeout', "%sms" % timeout))

        if filters:
            args.append(('filters', filters))

        if script_fields:
            args.append(('script_fields', script_fields))

        result = self._search(args, deep_paging_id=deep_paging_id, use_archive=use_archive,
                              track_total_hits=track_total_hits)

        ret_data = {
            "offset": int(offset),
            "rows": int(rows),
            "total": int(result['hits']['total']['value']),
            "items": [self._format_output(doc, field_list, as_obj=as_obj) for doc in result['hits']['hits']]
        }

        new_deep_paging_id = result.get("_scroll_id", None)

        # Check if the scroll is finished and close it
        if deep_paging_id is not None and new_deep_paging_id is None:
            self.with_retries(self.datastore.client.clear_scroll, body={"scroll_id": [deep_paging_id]}, ignore=(404,))

        # Check if we can tell from inspection that we have finished the scroll
        if new_deep_paging_id is not None and len(ret_data["items"]) < ret_data["rows"]:
            self.with_retries(self.datastore.client.clear_scroll,
                              body={"scroll_id": [new_deep_paging_id]}, ignore=(404,))
            new_deep_paging_id = None

        if new_deep_paging_id is not None:
            ret_data['next_deep_paging_id'] = new_deep_paging_id

        return ret_data

    def stream_search(self, query, fl=None, filters=None, access_control=None,
                      item_buffer_size=200, as_obj=True, use_archive=False):
        if item_buffer_size > 500 or item_buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 500.")

        index = self.name
        if self.archive_access and use_archive:
            index = f"{index},{self.name}-*"

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        if access_control:
            filters.append(access_control)

        if fl:
            fl = fl.split(',')

        query_body = {
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": query,
                            "default_field": self.DEFAULT_SEARCH_FIELD
                        }
                    },
                    'filter': [{'query_string': {'query': ff}} for ff in filters]
                }
            },
            "sort": parse_sort(self.datastore.DEFAULT_SORT),
            "_source": fl or list(self.stored_fields.keys())
        }

        iterator = RetryableIterator(
            self,
            elasticsearch.helpers.scan(
                self.datastore.client,
                query=query_body,
                index=index,
                preserve_order=True
            )
        )

        for value in iterator:
            # Unpack the results, ensure the id is always set
            yield self._format_output(value, fl, as_obj=as_obj)

    def histogram(self, field, start, end, gap, query="id:*", mincount=1,
                  filters=None, access_control=None, use_archive=False):
        type_modifier = self._validate_steps_count(start, end, gap)
        start = type_modifier(start)
        end = type_modifier(end)
        gap = type_modifier(gap)

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]
        filters.append('{field}:[{min} TO {max}]'.format(field=field, min=start, max=end))

        args = [
            ('query', query),
            ('histogram_active', True),
            ('histogram_field', field),
            ('histogram_type', "date_histogram" if isinstance(gap, str) else 'histogram'),
            ('histogram_gap', gap.strip('+') if isinstance(gap, str) else gap),
            ('histogram_mincount', mincount),
            ('histogram_start', start),
            ('histogram_end', end)
        ]

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args, use_archive=use_archive)

        # Convert the histogram into a dictionary
        return {type_modifier(row.get('key_as_string', row['key'])): row['doc_count']
                for row in result['aggregations']['histogram']['buckets']}

    def facet(self, field, query="id:*", prefix=None, contains=None, ignore_case=False, sort=None, limit=10,
              mincount=1, filters=None, access_control=None, use_archive=False):
        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('facet_active', True),
            ('facet_fields', [field]),
            ('facet_mincount', mincount),
            ('rows', 0)
        ]

        # TODO: prefix, contains, ignore_case, sort

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args, use_archive=use_archive)

        # Convert the histogram into a dictionary
        return {row.get('key_as_string', row['key']): row['doc_count']
                for row in result['aggregations'][field]['buckets']}

    def stats(self, field, query="id:*", filters=None, access_control=None, use_archive=False):
        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('stats_active', True),
            ('stats_fields', [field]),
            ('rows', 0)
        ]

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args, use_archive=use_archive)
        return result['aggregations'][f"{field}_stats"]

    def grouped_search(self, group_field, query="id:*", offset=0, sort=None, group_sort=None, fl=None, limit=1,
                       rows=None, filters=None, access_control=None, as_obj=True, use_archive=False,
                       track_total_hits=False):
        if rows is None:
            rows = self.DEFAULT_ROW_SIZE

        if sort is None:
            sort = self.DEFAULT_SORT

        if group_sort is None:
            group_sort = self.DEFAULT_SORT

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('group_active', True),
            ('group_field', group_field),
            ('group_limit', limit),
            ('group_sort', group_sort),
            ('start', offset),
            ('rows', rows),
            ('sort', sort)
        ]

        filters.append("%s:*" % group_field)

        if fl:
            field_list = fl.split(',')
            args.append(('field_list', field_list))
        else:
            field_list = None

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args, use_archive=use_archive, track_total_hits=track_total_hits)

        return {
            'offset': offset,
            'rows': rows,
            'total': int(result['hits']['total']['value']),
            'items': [{
                'value': collapsed['fields'][group_field][0],
                'total': int(collapsed['inner_hits']['group']['hits']['total']['value']),
                'items': [self._format_output(row, field_list, as_obj=as_obj)
                          for row in collapsed['inner_hits']['group']['hits']['hits']]
            } for collapsed in result['hits']['hits']]
        }

    @staticmethod
    def _get_odm_type(ds_type):
        try:
            return back_mapping[ds_type].__name__.lower()
        except KeyError:
            return ds_type.lower()

    def fields(self):

        def flatten_fields(props):
            out = {}
            for name, value in props.items():
                if 'properties' in value:
                    for child, cprops in flatten_fields(value['properties']).items():
                        out[name + '.' + child] = cprops
                elif 'type' in value:
                    out[name] = value
                else:
                    raise ValueError("Unknown field data " + str(props))
            return out

        data = self.with_retries(self.datastore.client.indices.get, self.name)
        index_name = list(data.keys())[0]
        properties = flatten_fields(data[index_name]['mappings'].get('properties', {}))

        if self.model_class:
            model_fields = self.model_class.flat_fields()
        else:
            model_fields = {}

        collection_data = {}

        for p_name, p_val in properties.items():
            if p_name.startswith("_") or "//" in p_name:
                continue
            if not Collection.FIELD_SANITIZER.match(p_name):
                continue

            field_model = model_fields.get(p_name, None)
            f_type = self._get_odm_type(p_val.get('analyzer', None) or p_val['type'])
            collection_data[p_name] = {
                "default": self.DEFAULT_SEARCH_FIELD in p_val.get('copy_to', []),
                "indexed": p_val.get('index', p_val.get('enabled', True)),
                "list": field_model.multivalued if field_model else False,
                "stored": field_model.store if field_model else False,
                "type": f_type
            }

        return collection_data

    def _ilm_policy_exists(self):
        conn = self.datastore.client.transport.get_connection()
        pol_req = conn.session.get(f"{conn.base_url}/_ilm/policy/{self.name}_policy")
        return pol_req.ok

    def _delete_ilm_policy(self):
        conn = self.datastore.client.transport.get_connection()
        pol_req = conn.session.delete(f"{conn.base_url}/_ilm/policy/{self.name}_policy")
        return pol_req.ok

    def _create_ilm_policy(self):
        data_base = {
            "policy": {
                "phases": {
                    "hot": {
                        "min_age": "0ms",
                        "actions": {
                            "set_priority": {
                                "priority": 100
                            },
                            "rollover": {
                                "max_age": f"{self.ilm_config['warm']}{self.ilm_config['unit']}"
                            }
                        }
                    },
                    "warm": {
                        "actions": {
                            "set_priority": {
                                "priority": 50
                            }
                        }
                    },
                    "cold": {
                        "min_age": f"{self.ilm_config['cold']}{self.ilm_config['unit']}",
                        "actions": {
                            "set_priority": {
                                "priority": 20
                            }
                        }
                    }
                }
            }
        }

        if self.ilm_config['delete']:
            data_base['policy']['phases']['delete'] = {
                "min_age": f"{self.ilm_config['delete']}{self.ilm_config['unit']}",
                "actions": {
                    "delete": {}
                }
            }

        conn = self.datastore.client.transport.get_connection()
        pol_req = conn.session.put(f"{conn.base_url}/_ilm/policy/{self.name}_policy",
                                   headers={"Content-Type": "application/json"},
                                   data=json.dumps(data_base))
        if not pol_req.ok:
            raise ILMException(f"ERROR: Failed to create ILM policy: {self.name}_policy")

    def _get_index_definition(self):
        index_def = deepcopy(default_index)
        if 'settings' not in index_def:
            index_def['settings'] = {}
        if 'index' not in index_def['settings']:
            index_def['settings']['index'] = {}
        index_def['settings']['index']['number_of_shards'] = self.shards
        index_def['settings']['index']['number_of_replicas'] = self.replicas

        mappings = deepcopy(default_mapping)
        if self.model_class:
            mappings['properties'], mappings['dynamic_templates'] = \
                build_mapping(self.model_class.fields().values())
            mappings['dynamic_templates'].insert(0, default_dynamic_strings)
        else:
            mappings['dynamic_templates'] = deepcopy(default_dynamic_templates)

        if not mappings['dynamic_templates']:
            # Setting dynamic to strict prevents any documents with fields not in the properties to be added
            mappings['dynamic'] = "strict"

        mappings['properties']['id'] = {
            "store": True,
            "doc_values": True,
            "type": 'keyword'
        }

        mappings['properties']['__text__'] = {
            "store": False,
            "type": 'text',
        }

        index_def['mappings'] = mappings

        return index_def

    def _ensure_collection(self):
        # Create HOT index
        if not self.with_retries(self.datastore.client.indices.exists, self.name):
            log.debug(f"Index {self.name.upper()} does not exists. Creating it now...")
            try:
                self.with_retries(self.datastore.client.indices.create, self.index_name, self._get_index_definition())
            except elasticsearch.exceptions.RequestError as e:
                if "resource_already_exists_exception" not in str(e):
                    raise
                log.warning(f"Tried to create an index template that already exists: {self.name.upper()}")

            self.with_retries(self.datastore.client.indices.put_alias, self.index_name, self.name)
        elif not self.with_retries(self.datastore.client.indices.exists, self.index_name) and \
                not self.with_retries(self.datastore.client.indices.exists_alias, self.name):
            # Turn on write block
            self.with_retries(self.datastore.client.indices.put_settings, body=write_block_settings)

            # Create a copy on the result index
            self._safe_index_copy(self.datastore.client.indices.clone, self.name, self.index_name)

            # Make the hot index the new clone
            alias_body = {"actions": [{"add":  {"index": self.index_name, "alias": self.name}}, {
                "remove_index": {"index": self.name}}]}
            self.with_retries(self.datastore.client.indices.update_aliases, alias_body)

            self.with_retries(self.datastore.client.indices.put_settings, body=write_unblock_settings)

        if self.ilm_config:
            # Create ILM policy
            while not self._ilm_policy_exists():
                try:
                    self.with_retries(self._create_ilm_policy)
                except ILMException:
                    time.sleep(0.1)
                    pass

            # Create WARM index template
            if not self.with_retries(self.datastore.client.indices.exists_template, self.name):
                log.debug(f"Index template {self.name.upper()} does not exists. Creating it now...")

                index = self._get_index_definition()

                index["index_patterns"] = [f"{self.name}-*"]
                index["order"] = 1
                index["settings"]["index.lifecycle.name"] = f"{self.name}_policy"
                index["settings"]["index.lifecycle.rollover_alias"] = f"{self.name}-archive"

                try:
                    self.with_retries(self.datastore.client.indices.put_template, self.name, index)
                except elasticsearch.exceptions.RequestError as e:
                    if "resource_already_exists_exception" not in str(e):
                        raise
                    log.warning(f"Tried to create an index template that already exists: {self.name.upper()}")

            if not self.with_retries(self.datastore.client.indices.exists_alias, f"{self.name}-archive"):
                log.debug(f"Index alias {self.name.upper()}-archive does not exists. Creating it now...")

                index = {"aliases": {f"{self.name}-archive": {"is_write_index": True}}}

                try:
                    self.with_retries(self.datastore.client.indices.create, f"{self.name}-000001", index)
                except elasticsearch.exceptions.RequestError as e:
                    if "resource_already_exists_exception" not in str(e):
                        raise
                    log.warning(f"Tried to create an index template that already exists: {self.name.upper()}-000001")

        self._check_fields()

    def _add_fields(self, missing_fields: Dict):
        no_fix = []
        properties = {}
        for name, field in missing_fields.items():
            # Figure out the path of the field in the document, if the name is set in the field, it
            # is going to be duplicated in the path from missing_fields, so drop it
            prefix = name.split('.')
            if field.name:
                prefix = prefix[:-1]

            # Build the fields and templates for this new mapping
            sub_properties, sub_templates = build_mapping([field], prefix=prefix, allow_refuse_implicit=False)
            properties.update(sub_properties)
            if sub_templates:
                no_fix.append(name)

        # If we have collected any fields that we can't just blindly add, as they might conflict
        # with existing things, (we might have the refuse_all_implicit_mappings rule in place)
        # simply raise an exception
        if no_fix:
            raise ValueError(f"Can't update database mapping for {self.name}, "
                             f"couldn't safely amend mapping for {no_fix}")

        # If we got this far, the missing fields have been described in properties, upload them to the
        # server, and we should be able to move on.
        mappings = {"properties": properties}
        for index in self.index_list_full:
            self.with_retries(self.datastore.client.indices.put_mapping, index=index, body=mappings)

        if self.with_retries(self.datastore.client.indices.exists_template, self.name):
            current_template = self.with_retries(self.datastore.client.indices.get_template, self.name)[self.name]
            recursive_update(current_template, {'mappings': mappings})
            self.with_retries(self.datastore.client.indices.put_template, self.name, body=current_template)

    def wipe(self):
        log.debug("Wipe operation started for collection: %s" % self.name.upper())

        for index in self.index_list:
            if self.with_retries(self.datastore.client.indices.exists, index):
                self.with_retries(self.datastore.client.indices.delete, index)

        if self.with_retries(self.datastore.client.indices.exists_template, self.name):
            self.with_retries(self.datastore.client.indices.delete_template, self.name)

        self._ensure_collection()


class ESStore(BaseStore):
    """ Elasticsearch multi-index implementation of the ResultStore interface."""
    DEFAULT_SORT = "id asc"
    DATE_FORMAT = {
        'NOW': 'now',
        'YEAR': 'y',
        'MONTH': 'M',
        'WEEK': 'w',
        'DAY': 'd',
        'HOUR': 'h',
        'MINUTE': 'm',
        'SECOND': 's',
        'MILLISECOND': 'ms',
        'MICROSECOND': 'micros',
        'NANOSECOND': 'nanos',
        'SEPARATOR': '||',
        'DATE_END': 'Z'
    }

    def __init__(self, hosts, collection_class=ESCollection, archive_access=True):
        config = forge.get_config()
        if config.datastore.ilm.enabled:
            ilm_config = config.datastore.ilm.indexes.as_primitives()
        else:
            ilm_config = {}

        super(ESStore, self).__init__(hosts, collection_class, ilm_config=ilm_config)
        tracer = logging.getLogger('elasticsearch')
        tracer.setLevel(logging.CRITICAL)

        self.client = elasticsearch.Elasticsearch(hosts=hosts,
                                                  connection_class=elasticsearch.RequestsHttpConnection,
                                                  max_retries=0,
                                                  timeout=TRANSPORT_TIMEOUT)
        self.archive_access = archive_access
        self.url_path = 'elastic'

    def __str__(self):
        return '{0} - {1}'.format(self.__class__.__name__, self._hosts)

    def ping(self):
        return self.client.ping()

    def close(self):
        super().close()
        self.client = None

    def connection_reset(self):
        self.client = elasticsearch.Elasticsearch(hosts=self._hosts,
                                                  connection_class=elasticsearch.RequestsHttpConnection,
                                                  max_retries=0,
                                                  timeout=TRANSPORT_TIMEOUT)
