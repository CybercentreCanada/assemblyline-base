from __future__ import annotations

import base64
import json
import logging
import re
import time
import typing
import warnings

from copy import deepcopy
from datemath import dm
from datemath.helpers import DateMathException
from datetime import datetime
from enum import Enum
from os import environ
from typing import Dict, Any, Union, TypeVar, Generic

import elasticsearch
import elasticsearch.helpers

from assemblyline import odm
from assemblyline.common.dict_utils import recursive_update
from assemblyline.datastore.bulk import ElasticBulkPlan
from assemblyline.datastore.exceptions import (DataStoreException, MultiKeyError, SearchException, ArchiveDisabled)
from assemblyline.datastore.support.build import back_mapping, build_mapping
from assemblyline.datastore.support.schemas import (default_dynamic_strings, default_dynamic_templates,
                                                    default_index, default_mapping)
from assemblyline.odm.base import BANNED_FIELDS, Keyword, Integer, List, Mapping, Model, ClassificationObject, _Field


if typing.TYPE_CHECKING:
    from .store import ESStore


log = logging.getLogger('assemblyline.datastore')
ModelType = TypeVar('ModelType', bound=Model)
write_block_settings = {"index.blocks.write": True}
write_unblock_settings = {"index.blocks.write": None}

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
        - convert any sorts on the key _id to id
    """
    if sort is None:
        return sort

    if isinstance(sort, list):
        return [parse_sort(row, ret_list=False) for row in sort]
    elif isinstance(sort, dict):
        return {('id' if key == '_id' else key): value for key, value in sort.items()}
    elif "," in sort:
        return [parse_sort(row.strip(), ret_list=False) for row in sort.split(',')]

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


class Index (Enum):
    HOT = 1
    ARCHIVE = 2
    HOT_AND_ARCHIVE = 3


class ESCollection(Generic[ModelType]):
    DEFAULT_ROW_SIZE = 25
    DEFAULT_SEARCH_FIELD = '__text__'
    DEFAULT_SORT = [{'_id': 'asc'}]
    FIELD_SANITIZER = re.compile("^[a-z][a-z0-9_\\-.]+$")
    MAX_GROUP_LIMIT = 10
    MAX_HISTOGRAM_STEPS = 100
    MAX_RETRY_BACKOFF = 10
    MAX_SEARCH_ROWS = 500
    RETRY_NORMAL = 1
    RETRY_NONE = 0
    RETRY_INFINITY = -1
    KEEP_ALIVE = "5m"
    UPDATE_SET = "SET"
    UPDATE_INC = "INC"
    UPDATE_DEC = "DEC"
    UPDATE_MAX = "MAX"
    UPDATE_MIN = "MIN"
    UPDATE_APPEND = "APPEND"
    UPDATE_APPEND_IF_MISSING = "APPEND_IF_MISSING"
    UPDATE_PREPEND = "PREPEND"
    UPDATE_PREPEND_IF_MISSING = "PREPEND_IF_MISSING"
    UPDATE_REMOVE = "REMOVE"
    UPDATE_DELETE = "DELETE"
    UPDATE_OPERATIONS = [
        UPDATE_APPEND,
        UPDATE_APPEND_IF_MISSING,
        UPDATE_DEC,
        UPDATE_INC,
        UPDATE_MAX,
        UPDATE_MIN,
        UPDATE_PREPEND,
        UPDATE_PREPEND_IF_MISSING,
        UPDATE_REMOVE,
        UPDATE_SET,
        UPDATE_DELETE,
    ]
    DEFAULT_SEARCH_VALUES: dict[str, typing.Any] = {
        'timeout': None,
        'field_list': None,
        'facet_active': False,
        'facet_mincount': 1,
        'facet_fields': [],
        'stats_active': False,
        'stats_fields': [],
        'field_script': None,
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
        'rows': DEFAULT_ROW_SIZE,
        'query': "*",
        'sort': DEFAULT_SORT,
        'df': None,
        'script_fields': []
    }

    def __init__(self, datastore: ESStore, name, model_class=None, validate=True):
        self.replicas = environ.get(f"ELASTIC_{name.upper()}_REPLICAS", environ.get('ELASTIC_DEFAULT_REPLICAS', 0))
        self.shards = environ.get(f"ELASTIC_{name.upper()}_SHARDS", environ.get('ELASTIC_DEFAULT_SHARDS', 1))
        self.archive_replicas = environ.get(f"ELASTIC_{name.upper()}_ARCHIVE_REPLICAS", self.replicas)
        self.archive_shards = environ.get(f"ELASTIC_{name.upper()}_ARCHIVE_SHARDS", self.shards)

        self.datastore = datastore
        self.name = name
        self.index_name = f"{name}_hot"

        # Initialize archive
        self.archive_name = None
        self.index_archive_name = None
        if name in datastore.archive_indices:
            self.archive_name = f"{name}-ma"
            self.index_archive_name = f"{name}-ma_hot"

        self.model_class = model_class
        self.validate = validate

        self._ensure_collection()

        self.stored_fields = {}
        if model_class:
            for name, field in model_class.flat_fields().items():
                if field.store:
                    self.stored_fields[name] = field

    def is_archive_index(self, index):
        return self.archive_name and index.startswith(self.archive_name)

    def get_index_list(self, index_type):
        # Default value
        if index_type is None:
            # If has an archive: hot + archive
            if self.archive_name and self.datastore.archive_access:
                return [self.name, self.archive_name]
            # Otherwise just hot
            return [self.name]

        # If specified index is HOT
        elif index_type == Index.HOT:
            return [self.name]

        # If only archive asked
        elif index_type == Index.ARCHIVE:
            # Crash if index has no archive
            if not self.archive_name:
                raise ArchiveDisabled(f"Index {self.name.upper()} does not have an archive")

            # Crash if no archive access
            if not self.datastore.archive_access:
                raise ArchiveDisabled(
                    "Trying to get access to the archive on a datastore where archive_access is disabled")

            # Return only archive index
            return [self.archive_name]
        else:
            # Crash if no archive access
            if not self.datastore.archive_access:
                raise ArchiveDisabled(
                    "Trying to get access to the archive on a datastore where archive_access is disabled")

            # Return HOT if asked for both but only has HOT
            if not self.archive_name:
                return [self.name]

            # Otherwise return hot and archive indices
            return [self.name, self.archive_name]

    def get_joined_index(self, index_type):
        return ",".join(self.get_index_list(index_type))

    def scan_with_search_after(self, query, sort=None, source=None, index=None, keep_alive=KEEP_ALIVE, size=1000,
                               timeout=None):
        if index is None:
            index = self.name
        if not sort:
            sort = []

        # Generate the point in time
        pit = {'id': self.with_retries(self.datastore.client.open_point_in_time,
                                       index=index, keep_alive=keep_alive)['id'],
               'keep_alive': keep_alive}

        # Add tie_breaker sort using _shard_doc ID
        sort.append({"_shard_doc": "desc"})

        # initial search
        resp = self.with_retries(self.datastore.client.search, query=query, pit=pit,
                                 size=size, timeout=timeout, sort=sort, _source=source)
        try:
            while resp["hits"]["hits"]:
                search_after = resp['hits']['hits'][-1]['sort']
                for hit in resp["hits"]["hits"]:
                    yield hit

                resp = self.with_retries(self.datastore.client.search, query=query, pit=pit,
                                         size=size, timeout=timeout, sort=sort, _source=source,
                                         search_after=search_after)

        finally:
            try:
                self.with_retries(self.datastore.client.close_point_in_time, id=pit['id'])
            except elasticsearch.exceptions.NotFoundError:
                pass

    def with_retries(self, func, *args, **kwargs):
        """
        This function performs the passed function with the given args and kwargs and reconnect if it fails

        :return: return the output of the function passed
        """
        retries = 0
        while True:
            try:
                return self.datastore.with_retries(func, *args, **kwargs)
            except elasticsearch.exceptions.NotFoundError as e:
                if "index_not_found_exception" in str(e):
                    time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                    log.debug("The index does not exist. Trying to recreate it...")
                    self._ensure_collection()
                    retries += 1
                else:
                    raise

    @staticmethod
    def _normalize_output(data_output):
        if "__non_doc_raw__" in data_output:
            return data_output['__non_doc_raw__']
        data_output.pop('id', None)
        return data_output

    def _get_current_alias(self, index: str) -> typing.Optional[str]:
        if self.with_retries(self.datastore.client.indices.exists_alias, name=index):
            return next(iter(self.with_retries(self.datastore.client.indices.get_alias, index=index)), None)
        return None

    def _wait_for_status(self, index, min_status='yellow'):
        status_ok = False
        while not status_ok:
            try:
                res = self.datastore.client.cluster.health(index=index, timeout='5s', wait_for_status=min_status)
                status_ok = not res['timed_out']
            except elasticsearch.exceptions.TransportError as e:
                err_code, _, _ = e.args
                if err_code == 408 or err_code == '408':
                    log.warning(f"Waiting for index {index} to get to status {min_status}...")
                    pass
                else:
                    raise
            except elasticsearch.ApiError as err:
                if err.meta.status == 408:
                    log.warning(f"Waiting for index {index} to get to status {min_status}...")
                    pass
                else:
                    raise

    def _safe_index_copy(self, copy_function, src, target, settings=None, min_status='yellow'):
        ret = copy_function(index=src, target=target, settings=settings, timeout='60s')
        if not ret['acknowledged']:
            raise DataStoreException(f"Failed to create index {target} from {src}.")

        self._wait_for_status(target, min_status=min_status)

    def _delete_async(self, index, query, max_docs=None, sort=None):
        deleted = 0
        while True:
            task = self.with_retries(self.datastore.client.delete_by_query, index=index,
                                     query=query, wait_for_completion=False, conflicts='proceed',
                                     sort=sort, max_docs=max_docs)
            res = self.datastore._get_task_results(task, retry_function=self.with_retries)

            if res['version_conflicts'] == 0:
                res['deleted'] += deleted
                return res
            else:
                deleted += res['deleted']

    def _update_async(self, index, script, query, max_docs=None):
        updated = 0
        while True:
            task = self.with_retries(
                self.datastore.client.update_by_query, index=index, script=script, query=query,
                wait_for_completion=False, conflicts='proceed', max_docs=max_docs)
            res = self.datastore._get_task_results(task, retry_function=self.with_retries)

            if res['version_conflicts'] == 0:
                res['updated'] += updated
                return res
            else:
                updated += res['updated']

    def restore_old_archive(self, delete_after=False):
        """
        This function moves documents that were previously in the old archiving system back to the hot index

        :param delete_after: Delete everything related to the old archive when the data move is complete
        :return: Number documents restaured
        """
        source = {
            "index": f"{self.name}-0*",
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": "id:*"
                        }
                    }
                }
            },
        }

        dest = {
            "index": f"{self.name}"
        }

        r_task = self.with_retries(self.datastore.client.reindex, source=source, dest=dest, wait_for_completion=False)
        res = self.datastore._get_task_results(r_task, retry_function=self.with_retries)
        total_restaured = res['updated'] + res['created']

        if delete_after:
            # Remove ILM Policy
            ilm_name = f"{self.name}_policy"
            try:
                res = self.with_retries(self.datastore.client.ilm.get_lifecycle, name=ilm_name)
                for index in res.get(ilm_name, {}).get('in_use_by', {}).get('indices', []):
                    self.with_retries(self.datastore.client.ilm.remove_policy, index=index)
                self.with_retries(self.datastore.client.ilm.delete_lifecycle, name=ilm_name)
            except elasticsearch.NotFoundError:
                pass

            # Delete index templates for old archive
            if self.with_retries(self.datastore.client.indices.exists_template, name=self.name):
                self.with_retries(self.datastore.client.indices.delete_template, name=self.name)

            # Delete old archive alias
            alias = f"{self.name}-archive"
            if self.with_retries(self.datastore.client.indices.exists_alias, name=alias):
                self.with_retries(self.datastore.client.indices.delete_alias, index=source['index'], name=alias)

            # Delete old archive indices
            self.with_retries(self.datastore.client.indices.delete, index=source['index'], allow_no_indices=True)

        return total_restaured

    def archive(self, key, delete_after=False, allow_missing=False):
        """
        Copy/Move a single document into the archive and return the document that was archived.

        :param key: ID of the document to copy or move to the archive
        :param allow_missing: If True, does not crash if the document you are trying to archive is missing
        :param delete_after: Delete the document from hot storage after archive
        """
        if not self.archive_name:
            raise ArchiveDisabled("This datastore object does not have archive access.")

        # Check if already in archive
        if not self.exists(key, index_type=Index.ARCHIVE):
            # Get the document from hot index
            doc = self.get_if_exists(key, index_type=Index.HOT)
            if doc:
                # Reset Expiry if present
                try:
                    doc.expiry_ts = None
                except (AttributeError, KeyError, ValueError):
                    pass

                # Save the document to the archive
                self.save(key, doc, index_type=Index.ARCHIVE)
            elif not allow_missing:
                raise DataStoreException(f"{key} does not exists in {self.name} hot index therefor cannot be archived.")

        if delete_after:
            self.delete(key, index_type=Index.HOT)

        return True

    def archive_by_query(self, query, max_docs=None, sort=None, delete_after=False):
        """
        This function should archive to document that are matching to query to an time splitted index

        :param query: query to run to archive documents
        :return: Number of archived documents
        """
        if not self.archive_name:
            raise ArchiveDisabled("This datastore object does not have archive access.")

        source = {
            "index": self.name,
            "query": {
                "bool": {
                    "must": {
                        "query_string": {
                            "query": query
                        }
                    }
                }
            }
        }
        dest = {
            "index": self.archive_name
        }
        if max_docs:
            source['size'] = max_docs

        if sort:
            source['sort'] = parse_sort(sort)

        r_task = self.with_retries(self.datastore.client.reindex, source=source, dest=dest, wait_for_completion=False)
        res = self.datastore._get_task_results(r_task, retry_function=self.with_retries)
        total_archived = res['updated'] + res['created']
        if res['total'] == total_archived or max_docs == total_archived:
            if total_archived != 0 and delete_after:
                info = self._delete_async(self.name, query={"bool": {"must": {"query_string": {"query": query}}}},
                                          max_docs=max_docs, sort=sort_str(parse_sort(sort)))
                return info.get('deleted', 0) == total_archived
            else:
                return True
        else:
            return False

    def bulk(self, operations):
        """
        Receives a bulk plan and executes the plan.

        :return: Results of the bulk operation
        """

        if not isinstance(operations, ElasticBulkPlan):
            return TypeError("Operations must be of type ElasticBulkPlan")

        return self.with_retries(self.datastore.client.bulk, operations=operations.get_plan_data())

    def get_bulk_plan(self, index_type=None):
        """
        Creates a BulkPlan tailored for the current datastore

        :param index_type: Type of indices to target
        :return: The BulkPlan object
        """
        return ElasticBulkPlan(self.get_index_list(index_type), model=self.model_class)

    def commit(self, index_type=None):
        """
        This function should be overloaded to perform a commit of the index data of all the different hosts
        specified in self.datastore.hosts.

        :param index_type: Type of indices to target
        :return: Should return True of the commit was successful on all hosts
        """
        for index in self.get_index_list(index_type):
            self.with_retries(self.datastore.client.indices.refresh, index=index)
            self.with_retries(self.datastore.client.indices.clear_cache, index=index)
        return True

    def fix_replicas(self, index_type=None):
        """
        This function should be overloaded to fix the replica configuration of the index of all the different hosts
        specified in self.datastore.hosts.

        :param index_type: Type of indices to target
        :return: Should return True of the fix was successful on all hosts
        """
        results = []
        for index in self.get_index_list(index_type):
            replicas = self._get_index_settings(archive=self.is_archive_index(index))['index']['number_of_replicas']
            settings = {"number_of_replicas": replicas}
            results.append(self.with_retries(
                self.datastore.client.indices.put_settings, index=index, settings=settings)['acknowledged'])
        return all(results)

    def fix_shards(self, logger=None, index_type=None):
        """
        This function should be overloaded to fix the shard configuration of the index of all the different hosts
        specified in self.datastore.hosts.

        :param index_type: Type of indices to target
        :return: Should return True of the fix was successful on all hosts
        """
        if logger is None:
            logger = log

        for name in self.get_index_list(index_type):
            index = f"{name}_hot"
            logger.info(f'Processing index: {index.upper()}')
            settings = self._get_index_settings(archive=self.is_archive_index(name))
            index_copy_settings = {"index.number_of_replicas": 0}
            clone_finish_settings = None
            clone_setup_settings = None
            method = None
            target_node = ""
            temp_name = f'{name}__fix_shards'

            indexes_settings = self.with_retries(self.datastore.client.indices.get_settings, index=name)
            current_settings = indexes_settings.get(self._get_current_alias(name), None)
            if not current_settings:
                raise DataStoreException(
                    'Could not get current index settings. Something is wrong and requires manual intervention...')

            cur_replicas = int(current_settings['settings']['index']['number_of_replicas'])
            cur_shards = int(current_settings['settings']['index']['number_of_shards'])
            target_shards = int(settings['index']['number_of_shards'])
            clone_finish_settings = {"index.number_of_replicas": cur_replicas,
                                     "index.routing.allocation.require._name": None}

            if cur_shards > target_shards:
                logger.info(f"Current shards ({cur_shards}) is bigger then target shards ({target_shards}), "
                            "we will be shrinking the index.")
                if cur_shards % target_shards != 0:
                    logger.info("The target shards is not a factor of the current shards, aborting...")
                    return
                else:
                    target_node = self.with_retries(self.datastore.client.cat.nodes, format='json')[0]['name']
                    clone_setup_settings = {"index.number_of_replicas": 0,
                                            "index.routing.allocation.require._name": target_node}
                    method = self.datastore.client.indices.shrink
            elif cur_shards < target_shards:
                logger.info(f"Current shards ({cur_shards}) is smaller then target shards ({target_shards}), "
                            "we will be splitting the index.")
                if target_shards % cur_shards != 0:
                    logger.info("The current shards is not a factor of the target shards, aborting...")
                    return
                else:
                    method = self.datastore.client.indices.split
            else:
                logger.info(f"Current shards ({cur_shards}) is equal to the target shards ({target_shards}), "
                            "only house keeping operations will be performed.")

            if method:
                # Before we do anything, we should make sure the source index is in a good state
                logger.info(f"Waiting for {name.upper()} status to be GREEN.")
                self._wait_for_status(name, min_status='green')

                # Block all indexes to be written to
                logger.info("Set a datastore wide write block on Elastic.")
                self.with_retries(self.datastore.client.indices.put_settings, index=name, settings=write_block_settings)

                # Clone it onto a temporary index
                if not self.with_retries(self.datastore.client.indices.exists, index=temp_name):
                    # if there are specific settings to be applied to the index, apply them
                    if clone_setup_settings:
                        logger.info(f"Rellocating index to node {target_node.upper()}.")
                        self.with_retries(self.datastore.client.indices.put_settings,
                                          index=index, settings=clone_setup_settings)

                        # Make sure no shard are relocating
                        while self.datastore.client.cluster.health(index=index)['relocating_shards'] != 0:
                            time.sleep(1)

                    # Make a clone of the current index
                    logger.info(f"Cloning {index.upper()} into {temp_name.upper()}.")
                    self._safe_index_copy(self.datastore.client.indices.clone,
                                          index, temp_name, settings=index_copy_settings, min_status='green')

                # Make 100% sure temporary index is ready
                logger.info(f"Waiting for {temp_name.upper()} status to be GREEN.")
                self._wait_for_status(temp_name, 'green')

                # Make sure temporary index is the alias if not already
                if self._get_current_alias(name) != temp_name:
                    logger.info(f"Make {temp_name.upper()} the current alias for {name.upper()} "
                                f"and delete {index.upper()}.")
                    # Make the hot index the temporary index while deleting the original index
                    actions = [{"add":  {"index": temp_name, "alias": name}}, {
                        "remove_index": {"index": index}}]
                    self.with_retries(self.datastore.client.indices.update_aliases, actions=actions)

                # Make sure the original index is deleted
                if self.with_retries(self.datastore.client.indices.exists, index=index):
                    logger.info(f"Delete extra {index.upper()} index.")
                    self.with_retries(self.datastore.client.indices.delete, index=index)

                # Shrink/split the temporary index into the original index
                logger.info(f"Perform shard fix operation from {temp_name.upper()} to {index.upper()}.")
                self._safe_index_copy(method, temp_name, index, settings=settings)

                # Make the original index the new alias
                logger.info(f"Make {index.upper()} the current alias for {name.upper()} "
                            f"and delete {temp_name.upper()}.")
                actions = [{"add":  {"index": index, "alias": name}}, {
                    "remove_index": {"index": temp_name}}]
                self.with_retries(self.datastore.client.indices.update_aliases, actions=actions)

            # Restore writes
            logger.info("Restore datastore wide write operation on Elastic.")
            self.with_retries(self.datastore.client.indices.put_settings, index=name, settings=write_unblock_settings)

            # Restore normal routing and replicas
            logger.info(f"Restore original routing table for {name.upper()}.")
            self.with_retries(self.datastore.client.indices.put_settings, index=name,
                              settings=clone_finish_settings)

    def reindex(self, index_type=None):
        """
        This function triggers a reindex of the current index, this should almost never be used because:
            1. There is no crash recovery
            2. Even if the system is still accessible during that time the data is partially accessible

        :param index_type: Type of indices to target
        :return: Should return True of the commit was successful on all hosts
        """
        for name in self.get_index_list(index_type):
            index = f"{name}_hot"
            archive = self.is_archive_index(index)
            new_name = f'{index}__reindex'
            if self.with_retries(self.datastore.client.indices.exists, index=index) and \
                    not self.with_retries(self.datastore.client.indices.exists, index=new_name):

                # Create reindex target
                self.with_retries(self.datastore.client.indices.create, index=new_name,
                                  mappings=self._get_index_mappings(),
                                  settings=self._get_index_settings(archive=archive))

                # Swap indices
                actions = [{"add": {"index": new_name, "alias": name}},
                           {"remove": {"index": index, "alias": name}}, ]
                self.with_retries(self.datastore.client.indices.update_aliases, actions=actions)

                # Reindex data into target
                r_task = self.with_retries(self.datastore.client.reindex, source={"index": index},
                                           dest={"index": new_name}, wait_for_completion=False)
                self.datastore._get_task_results(r_task, retry_function=self.with_retries)

                # Commit reindexed data
                self.with_retries(self.datastore.client.indices.refresh, index=new_name)
                self.with_retries(self.datastore.client.indices.clear_cache, index=new_name)

                # Delete old index
                self.with_retries(self.datastore.client.indices.delete, index=index)

                # Block write to the index
                self.with_retries(self.datastore.client.indices.put_settings, index=name, settings=write_block_settings)

                # Rename reindexed index
                try:
                    self._safe_index_copy(self.datastore.client.indices.clone, new_name, index,
                                          settings=self._get_index_settings(archive=archive))

                    # Restore original aliases for the index
                    actions = [{"add": {"index": index, "alias": name}},
                               {"remove": {"index": new_name, "alias": name}}, ]
                    self.with_retries(self.datastore.client.indices.update_aliases, actions=actions)

                    # Delete the reindex target if it still exists
                    if self.with_retries(self.datastore.client.indices.exists, index=new_name):
                        self.with_retries(self.datastore.client.indices.delete, index=new_name)
                finally:
                    # Unblock write to the index
                    self.with_retries(self.datastore.client.indices.put_settings,
                                      index=name, settings=write_unblock_settings)

        return True

    def multiexists(self, key_list, index_type=None):
        """
        With a list of keys, check if all those keys exists in the specified indices

        :param index_type: Type of indices to target
        :param key_list: list of keys to check if exists
        :return: dictionary with the exists result of all original keys
        """
        out = {k: False for k in key_list}

        if key_list:
            result = self.with_retries(
                self.datastore.client.search, index=self.get_joined_index(index_type),
                query={"ids": {"values": key_list}},
                source=['id'],
                size=len(key_list),
                collapse={'field': "id"})
            for row in result['hits']['hits']:
                out[row['_id']] = True

        return out

    def multiget(self, key_list, as_dictionary=True, as_obj=True, error_on_missing=True, index_type=None):
        """
        Get a list of documents from the datastore and make sure they are normalized using
        the model class

        :param index_type: Type of indices to target
        :param error_on_missing: Should it raise a key error when keys are missing
        :param as_dictionary: Return a disctionary of items or a list
        :param as_obj: Return objects or not
        :param key_list: list of keys of documents to get
        :return: list of instances of the model class
        """
        index_list = self.get_index_list(index_type)

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

        for index in index_list:
            if not key_list:
                break

            data = self.with_retries(self.datastore.client.mget, ids=key_list, index=index)

            for row in data.get('docs', []):
                if 'found' in row and not row['found']:
                    continue

                try:
                    key_list.remove(row['_id'])

                    # If this index has an archive, check is the document was found in it.
                    if self.archive_name:
                        row['_source']['from_archive'] = self.is_archive_index(index)

                    add_to_output(row['_source'], row['_id'])
                except ValueError:
                    log.error(f'MGet returned multiple documents for id: {row["_id"]}')

        if key_list and error_on_missing:
            raise MultiKeyError(key_list, out)

        return out

    def normalize(self, data, as_obj=True) -> Union[ModelType, Dict[str, Any], None]:
        """
        Normalize the data using the model class

        :param as_obj: Return an object instead of a dictionary
        :param data: data to normalize
        :return: instance of the model class
        """
        if as_obj and data is not None and self.model_class and not isinstance(data, self.model_class):
            return self.model_class(data)

        if isinstance(data, dict):
            data = {k: v for k, v in data.items() if k not in BANNED_FIELDS}

        return data

    def exists(self, key: str, index_type: typing.Optional[Index] = None) -> bool:
        """
        Check if a document exists in the datastore.

        :param index_type: Type of indices to target
        :param key: key of the document to get from the datastore
        :return: true/false depending if the document exists or not
        """
        index_list = self.get_index_list(index_type)
        found = False

        for index in index_list:
            found = self.with_retries(self.datastore.client.exists, index=index, id=key, _source=False)
            if found:
                break

        return found

    def _get(self, key, retries, index_type=None, version=False):
        """
        Versioned get-save for atomic update has three paths:
            1. Document doesn't exist at all. Create token will be returned for version.
               This way only the first query to try and create the document will succeed.
            2. Document exists. A version string with the info needed to do a versioned save is returned.

        The create token is needed to differentiate between "I'm saving a new
        document non-atomic (version=None)" and "I'm saving a new document
        atomically (version=CREATE_TOKEN)".
        """
        index_list = self.get_index_list(index_type)

        if retries is None:
            retries = self.RETRY_NONE

        done = False
        while not done:
            for index in index_list:
                try:
                    doc = self.with_retries(self.datastore.client.get, index=index, id=key)

                    # If this index has an archive, check is the document was found in it.
                    if self.archive_name:
                        doc['_source']['from_archive'] = self.is_archive_index(index)

                    if version:
                        return self._normalize_output(doc['_source']), f"{doc['_seq_no']}---{doc['_primary_term']}"
                    return self._normalize_output(doc['_source'])
                except elasticsearch.exceptions.NotFoundError:
                    pass

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

    @typing.overload
    def get(self, key: str, as_obj: typing.Literal[True] = True, index_type: typing.Optional[Index] = None,
            version=False) -> typing.Optional[ModelType]:
        ...

    @typing.overload
    def get(self, key: str, as_obj: typing.Literal[False], index_type: typing.Optional[Index] = None,
            version=False) -> typing.Optional[dict]:
        ...

    def get(self, key, as_obj=True, index_type=None, version=False):
        """
        Get a document from the datastore, retry a few times if not found and normalize the
        document with the model provided with the collection.

        This is the normal way to get data of the system.

        :param index_type: Type of indices to target
        :param as_obj: Should the data be returned as an ODM object
        :param key: key of the document to get from the datastore
        :param version: should the version number be returned by the call
        :return: an instance of the model class loaded with the document data
        """
        data = self._get(key, self.RETRY_NORMAL, index_type=index_type, version=version)
        if version:
            data, version = data
            return self.normalize(data, as_obj=as_obj), version
        return self.normalize(data, as_obj=as_obj)

    @typing.overload
    def get_if_exists(self, key: str, as_obj: typing.Literal[True] = True, index_type: typing.Optional[Index] = None,
                      version=False) -> typing.Optional[ModelType]:
        ...

    @typing.overload
    def get_if_exists(self, key: str, as_obj: typing.Literal[False], index_type: typing.Optional[Index] = None,
                      version=False) -> typing.Optional[dict]:
        ...

    def get_if_exists(self, key, as_obj=True, index_type=None, version=False):
        """
        Get a document from the datastore but do not retry if not found.

        Use this more in caching scenarios because eventually consistent database may lead
        to have document reported has missing even if they exist.

        :param index_type: Type of indices to target
        :param as_obj: Should the data be returned as an ODM object
        :param key: key of the document to get from the datastore
        :param version: should the version number be returned by the call
        :return: an instance of the model class loaded with the document data
        """
        data = self._get(key, self.RETRY_NONE, index_type=index_type, version=version)
        if version:
            data, version = data
            return self.normalize(data, as_obj=as_obj), version
        return self.normalize(data, as_obj=as_obj)

    def require(self, key, as_obj=True, index_type=None, version=False) -> Union[Dict[str, Any], ModelType]:
        """
        Get a document from the datastore and retry forever because we know for sure
        that this document should exist. If it does not right now, this will wait for the
        document to show up in the datastore.

        :param index_type: Type of indices to target
        :param as_obj: Should the data be returned as an ODM object
        :param key: key of the document to get from the datastore
        :param version: should the version number be returned by the call
        :return: an instance of the model class loaded with the document data
        """
        data = self._get(key, self.RETRY_INFINITY, index_type=index_type, version=version)
        if version:
            data, version = data
            return self.normalize(data, as_obj=as_obj), version
        return self.normalize(data, as_obj=as_obj)

    def save(self, key, data, version=None, index_type=Index.HOT):
        """
        Save a to document to the datastore using the key as its document id.

        The document data will be normalized before being saved in the datastore.

        :param index_type: Type of indices to target
        :param key: ID of the document to save
        :param data: raw data or instance of the model class to save as the document
        :param version: version of the document to save over, if the version check fails this will raise an exception
        :return: True if the document was saved properly
        """
        if " " in key:
            raise DataStoreException("You are not allowed to use spaces in datastore keys.")

        data = self.normalize(data)

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

        index_list = self.get_index_list(index_type)
        for index in index_list:
            self.with_retries(
                self.datastore.client.index,
                index=index,
                id=key,
                document=json.dumps(saved_data),
                op_type=operation,
                if_seq_no=seq_no,
                if_primary_term=primary_term,
                raise_conflicts=True
            )

        return True

    def delete(self, key, index_type=None):
        """
        This function should delete the underlying document referenced by the key.
        It should return true if the document was in fact properly deleted.

        :param index_type: Type of indices to target
        :param key: id of the document to delete
        :return: True is delete successful
        """
        index_list = self.get_index_list(index_type)

        deleted = False
        for index in index_list:
            try:
                info = self.with_retries(self.datastore.client.delete, id=key, index=index)
                deleted |= info['result'] == 'deleted'
            except elasticsearch.NotFoundError:
                deleted = True

        return deleted

    def delete_by_query(self, query, sort=None, max_docs=None, index_type=None):
        """
        This function should delete the underlying documents referenced by the query.
        It should return true if the documents were in fact properly deleted.

        :param index_type: Type of indices to target
        :param sort: In which order to delete the documens
        :param max_docs: maximum number of documents to delete
        :param query: Query of the documents to download
        :return: True is delete successful
        """
        index = self.get_joined_index(index_type)
        info = self._delete_async(index, query={"bool": {"must": {"query_string": {"query": query}}}},
                                  sort=sort_str(parse_sort(sort)), max_docs=max_docs)
        return info.get('deleted', 0)

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
                script = f"if (ctx._source.{doc_key} == null) " \
                         f"{{ctx._source.{doc_key} = new ArrayList()}} " \
                         f"ctx._source.{doc_key}.add(params.value{val_id})"
                op_sources.append(script)
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_APPEND_IF_MISSING:
                script = f"if (ctx._source.{doc_key} == null) " \
                         f"{{ctx._source.{doc_key} = new ArrayList()}} " \
                         f"if (ctx._source.{doc_key}.indexOf(params.value{val_id}) == -1) " \
                         f"{{ctx._source.{doc_key}.add(params.value{val_id})}}"
                op_sources.append(script)
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_PREPEND:
                op_sources.append(f"ctx._source.{doc_key}.add(0, params.value{val_id})")
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_PREPEND_IF_MISSING:
                script = f"if (ctx._source.{doc_key}.indexOf(params.value{val_id}) == -1) " \
                         f"{{ctx._source.{doc_key}.add(0, params.value{val_id})}}"
                op_sources.append(script)
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
            elif op == self.UPDATE_MAX:
                script = f"if (ctx._source.{doc_key} == null || " \
                         f"ctx._source.{doc_key}.compareTo(params.value{val_id}) < 0) " \
                         f"{{ctx._source.{doc_key} = params.value{val_id}}}"
                op_sources.append(script)
                op_params[f'value{val_id}'] = value
            elif op == self.UPDATE_MIN:
                script = f"if (ctx._source.{doc_key} == null || " \
                         f"ctx._source.{doc_key}.compareTo(params.value{val_id}) > 0) " \
                         f"{{ctx._source.{doc_key} = params.value{val_id}}}"
                op_sources.append(script)
                op_params[f'value{val_id}'] = value

            val_id += 1

        joined_sources = """;\n""".join(op_sources)

        script = {
            "lang": "painless",
            "source": joined_sources.replace("};\n", "}\n"),
            "params": op_params
        }
        return script

    def _validate_operations(self, operations):
        """
        Validate the different operations received for a partial update

        TODO: When the field is of type Mapping, the validation/check only works for depth 1. A full recursive
              solution is needed to support multi-depth cases.

        :param operations: list of operation tuples
        :raises: DatastoreException if operation not valid
        """
        if self.model_class:
            fields = self.model_class.flat_fields(show_compound=True)
            if 'classification in fields':
                fields.update({"__access_lvl__": Integer(),
                               "__access_req__": List(Keyword()),
                               "__access_grp1__": List(Keyword()),
                               "__access_grp2__": List(Keyword())})
        else:
            fields = None

        ret_ops = []
        for op, doc_key, value in operations:
            if op not in self.UPDATE_OPERATIONS:
                raise DataStoreException(f"Not a valid Update Operation: {op}")

            if fields is not None:
                prev_key = None
                if doc_key not in fields:
                    if '.' in doc_key:
                        prev_key = doc_key[:doc_key.rindex('.')]
                        if prev_key in fields and not isinstance(fields[prev_key], Mapping):
                            raise DataStoreException(f"Invalid field for model: {prev_key}")
                    else:
                        raise DataStoreException(f"Invalid field for model: {doc_key}")

                if prev_key:
                    field = fields[prev_key].child_type
                else:
                    field = fields[doc_key]

                if op in [self.UPDATE_APPEND, self.UPDATE_APPEND_IF_MISSING, self.UPDATE_PREPEND,
                          self.UPDATE_PREPEND_IF_MISSING, self.UPDATE_REMOVE]:
                    if not field.multivalued:
                        raise DataStoreException(f"Invalid operation for field {doc_key}: {op}")

                    try:
                        value = field.check(value)
                    except (ValueError, TypeError, AttributeError):
                        raise DataStoreException(f"Invalid value for field {doc_key}: {value}")

                elif op in [self.UPDATE_DEC, self.UPDATE_INC]:
                    try:
                        value = field.check(value)
                    except (ValueError, TypeError):
                        raise DataStoreException(f"Invalid value for field {doc_key}: {value}")

                elif op in [self.UPDATE_SET]:
                    try:
                        if field.multivalued and isinstance(value, list):
                            value = [field.check(v) for v in value]
                        else:
                            value = field.check(value)
                    except (ValueError, TypeError):
                        raise DataStoreException(f"Invalid value for field {doc_key}: {value}")

                if isinstance(value, Model):
                    value = value.as_primitives()
                elif isinstance(value, datetime):
                    value = value.isoformat()
                elif isinstance(value, ClassificationObject):
                    value = str(value)

            ret_ops.append((op, doc_key, value))

        return ret_ops

    def update(self, key, operations, index_type=Index.HOT):
        """
        This function performs an atomic update on some fields from the
        underlying documents referenced by the id using a list of operations.

        Operations supported by the update function are the following:
        INTEGER ONLY: Increase and decreased value
        LISTS ONLY: Append and remove items
        ALL TYPES: Set value

        :param index_type: Type of indices to target
        :param key: ID of the document to modify
        :param operations: List of tuple of operations e.q. [(SET, document_key, operation_value), ...]
        :return: True is update successful
        """
        operations = self._validate_operations(operations)
        script = self._create_scripts_from_operations(operations)
        index_list = self.get_index_list(index_type)

        for index in index_list:
            try:
                res = self.with_retries(self.datastore.client.update, index=index, id=key, script=script)
                return res['result'] == "updated"
            except elasticsearch.NotFoundError:
                pass
            except Exception:
                return False

        return False

    def update_by_query(self, query, operations, filters=None, access_control=None, max_docs=None,
                        index_type=Index.HOT):
        """
        This function performs an atomic update on some fields from the
        underlying documents matching the query and the filters using a list of operations.

        Operations supported by the update function are the following:
        INTEGER ONLY: Increase and decreased value
        LISTS ONLY: Append and remove items
        ALL TYPES: Set value

        :param index_type: Type of indices to target
        :param access_control:
        :param filters: Filter queries to reduce the data
        :param query: Query to find the matching documents
        :param operations: List of tuple of operations e.q. [(SET, document_key, operation_value), ...]
        :return: True is update successful
        """
        operations = self._validate_operations(operations)
        if filters is None:
            filters = []

        if access_control:
            filters.append(access_control)

        script = self._create_scripts_from_operations(operations)

        query_body = {
            "bool": {
                "must": {
                    "query_string": {
                        "query": query
                    }
                },
                'filter': [{'query_string': {'query': ff}} for ff in filters]
            }
        }

        try:
            res = self._update_async(
                self.get_joined_index(index_type),
                script=script, query=query_body, max_docs=max_docs)
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

        # If this index has an archive, check is the document was found in it.
        if self.archive_name:
            source_data['from_archive'] = self.is_archive_index(result['_index'])

        if self.model_class:
            if not fields:
                fields = list(self.stored_fields.keys())
                fields.append('id')
            elif isinstance(fields, str):
                fields = fields.split(',')

            extra_fields = _strip_lists(self.model_class, extra_fields)
            if as_obj:
                for f in fields:
                    if f.startswith("_") and f in result:
                        extra_fields[f] = result[f]
                if '*' in fields:
                    fields = None
                return self.model_class(source_data, mask=fields, docid=item_id, extra_fields=extra_fields)
            else:
                source_data = recursive_update(source_data, extra_fields)
                if 'id' in fields:
                    source_data['id'] = item_id
                for f in fields:
                    if f.startswith("_") and f in result:
                        source_data[f] = result[f]
                return source_data

        if isinstance(fields, str):
            fields = fields

        if fields is None or '*' in fields or 'id' in fields:
            source_data['id'] = item_id

        if fields is None or '*' in fields:
            return source_data

        return {key: val for key, val in source_data.items() if key in fields}

    def _search(self, args=None, deep_paging_id=None, track_total_hits=None, index_type=Index.HOT, key_space=None):
        index = self.get_joined_index(index_type)

        if args is None:
            args = []

        # Initialize values
        pit = None
        search_after = None

        # If there is deep_paging
        if deep_paging_id is not None:
            # If we have a properly formatted deep paging ID
            if "," in deep_paging_id:
                # Parse deep paging ID for pit_id and search_after
                pit_id, search_after_b64 = deep_paging_id.split(',')
                pit = {'id': pit_id, 'keep_alive': self.KEEP_ALIVE}
                search_after = json.loads(base64.b64decode(search_after_b64))

            else:
                # Create a new deep paging ID
                pit = {'id': self.with_retries(self.datastore.client.open_point_in_time,
                                               index=index, keep_alive=self.KEEP_ALIVE)['id'],
                       'keep_alive': self.KEEP_ALIVE}

            # Completely disable hit tracking to speed things up
            track_total_hits = False

        parsed_values = deepcopy(self.DEFAULT_SEARCH_VALUES)

        # TODO: we should validate values for max rows, group length, history length...
        for key, value in args:
            if key not in parsed_values:
                all_args = '; '.join('%s=%s' % (field_name, field_value) for field_name, field_value in args)
                raise ValueError("Unknown query argument: %s %s of [%s]" % (key, value, all_args))

            parsed_values[key] = value

        field_list = parsed_values['field_list'] or list(self.stored_fields.keys())

        filter_queries = [{'query_string': {'query': ff}} for ff in parsed_values['filters']]

        if key_space is not None:
            filter_queries.append({'ids': {'values': key_space}})

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
                    'filter': filter_queries
                }
            },
            'from_': parsed_values['start'],
            'size': parsed_values['rows'],
            'sort': parse_sort(parsed_values['sort']),
            "_source": field_list
        }

        if "_seq_no" in field_list or "_primary_term" in field_list:
            query_body["seq_no_primary_term"] = True

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
            query_body.setdefault("aggregations", {})
            if parsed_values['histogram_type'] == "date_histogram":
                interval_type = "fixed_interval"
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
            query_body.setdefault("aggregations", {})
            for field in parsed_values['facet_fields']:
                field_script = parsed_values['field_script']
                if field_script:
                    facet_body = {
                        "script": {
                            "source": field_script
                        },
                        "min_doc_count": parsed_values['facet_mincount']
                    }
                else:
                    facet_body = {
                        "field": field,
                        "min_doc_count": parsed_values['facet_mincount']
                    }
                query_body["aggregations"][field] = {
                    "terms": facet_body
                }

        # Add a stats aggregation
        if parsed_values['stats_active']:
            query_body.setdefault("aggregations", {})
            for field in parsed_values['stats_fields']:
                field_script = parsed_values['field_script']
                if field_script:
                    stats_body = {
                        "script": {
                            "source": field_script
                        }
                    }
                else:
                    stats_body = {
                        "field": field
                    }

                query_body["aggregations"][f"{field}_stats"] = {
                    "stats": stats_body
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
            # If we are using a Point in Time
            if pit:
                # Add a tie breaker sort field
                query_body['sort'].append({"_shard_doc": "desc"})
                # Get the next result page for PIT + Search After
                result = self.with_retries(self.datastore.client.search, pit=pit,
                                           search_after=search_after, track_total_hits=track_total_hits, **query_body)
            else:
                # Run the query
                result = self.with_retries(self.datastore.client.search, index=index,
                                           track_total_hits=track_total_hits, **query_body)

            return result

        except (elasticsearch.TransportError, elasticsearch.RequestError) as e:
            try:
                err_msg = e.info['error']['root_cause'][0]['reason']
            except (ValueError, KeyError, IndexError):
                err_msg = str(e)
            raise SearchException(err_msg)

        except Exception as error:
            raise SearchException("collection: %s, query: %s, error: %s" % (
                self.name, query_body, str(error))).with_traceback(error.__traceback__)

    def search(self, query, offset=0, rows=None, sort=None, fl=None, timeout=None, filters=None, access_control=None,
               deep_paging_id=None, as_obj=True, index_type=Index.HOT, track_total_hits=None, key_space=None,
               script_fields=[]):
        """
        This function should perform a search through the datastore and return a
        search result object that consist on the following::

            {
                "offset": 0,      # Offset in the search index
                "rows": 25,       # Number of document returned per page
                "total": 123456,  # Total number of documents matching the query
                "items": [        # List of dictionary where each keys are one of
                    {             #   the field list parameter specified
                        fl[0]: value,
                        ...
                        fl[x]: value
                    }, ...]
            }

        :param script_fields: List of name/script tuple of fields to be evaluated at runtime
        :param track_total_hits: Return to total matching document count
        :param index_type: Type of indices to target
        :param deep_paging_id: ID of the next page during deep paging searches
        :param as_obj: Return objects instead of dictionaries
        :param query: lucene query to search for
        :param offset: offset at which you want the results to start at (paging)
        :param rows: number of items that the search function should return
        :param sort: field to sort the data with
        :param fl: list of fields to return from the search
        :param timeout: maximum time of execution
        :param filters: additional queries to run on the original query to reduce the scope
        :param key_space: IDs of documents for the query to limit the scope to these documents
        :param access_control: access control parameters to limit the scope of the query
        :return: a search result object
        """

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

        result = self._search(args, deep_paging_id=deep_paging_id, index_type=index_type,
                              track_total_hits=track_total_hits, key_space=key_space)

        ret_data = {
            "offset": int(offset),
            "rows": int(rows),
            "total": result['hits'].get('total', {}).get('value', None),
            "items": [self._format_output(doc, field_list, as_obj=as_obj) for doc in result['hits']['hits']]
        }

        # If we where tracking total, change it into an INT
        if ret_data['total'] is not None:
            ret_data['total'] = int(ret_data['total'])

        # Get the currently used Point in Time if it exists
        pit_id = result.get("pit_id", None)

        # Check if deep paging is over
        if pit_id is not None and len(ret_data["items"]) < ret_data["rows"]:
            # Close the Point in Time
            try:
                self.with_retries(self.datastore.client.close_point_in_time, id=pit_id)
            except elasticsearch.exceptions.NotFoundError:
                pass

        elif pit_id is not None and len(ret_data["items"]) > 0:
            # We have a PIT ID and we don't seem to have finished looping throught the data
            # create the next deep paging id for the user to use.
            search_after = base64.b64encode(json.dumps(result['hits']['hits'][-1]['sort']).encode()).decode()
            ret_data['next_deep_paging_id'] = f"{pit_id},{search_after}"

        return ret_data

    def stream_search(self, query, fl=None, filters=None, access_control=None,
                      item_buffer_size=200, as_obj=True, index_type=Index.HOT):
        """
        This function should perform a search through the datastore and stream
        all related results as a dictionary of key value pair where each keys
        are one of the field specified in the field list parameter.

        >>> # noinspection PyUnresolvedReferences
        >>> {
        >>>     fl[0]: value,
        >>>     ...
        >>>     fl[x]: value
        >>> }

        :param query: lucene query to search for
        :param fl: list of fields to return from the search
        :param filters: additional queries to run on the original query to reduce the scope
        :param access_control: access control parameters to run the query with
        :param item_buffer_size: number of items to buffer with each search call
        :param as_obj: Return objects instead of dictionaries
        :param index_type: Type of indices to target
        :return: a generator of dictionary of field list results
        """
        if item_buffer_size > 2000 or item_buffer_size < 50:
            raise SearchException("Variable item_buffer_size must be between 50 and 2000.")

        index = self.get_joined_index(index_type)

        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        if access_control:
            filters.append(access_control)

        if fl:
            fl = fl.split(',')

        query_expression = {
            "bool": {
                "must": {
                    "query_string": {
                        "query": query,
                        "default_field": self.DEFAULT_SEARCH_FIELD
                    }
                },
                'filter': [{'query_string': {'query': ff}} for ff in filters]
            }
        }
        sort = parse_sort(self.datastore.DEFAULT_SORT)
        source = fl or list(self.stored_fields.keys())

        for value in self.scan_with_search_after(query=query_expression, sort=sort, source=source,
                                                 index=index, size=item_buffer_size):
            # Unpack the results, ensure the id is always set
            yield self._format_output(value, fl, as_obj=as_obj)

    def keys(self, access_control=None, index_type=Index.HOT):
        """
        This function streams the keys of all the documents of this collection.

        :param index_type: Type of indices to target
        :param access_control: access control parameter to limit the scope of the key scan
        :return: a generator of keys
        """
        for item in self.stream_search("id:*", fl='id', access_control=access_control, index_type=index_type):
            try:
                yield item.id
            except AttributeError:
                value = item['id']
                if isinstance(value, list):
                    for v in value:
                        yield v
                else:
                    yield value

    def _validate_steps_count(self, start, end, gap) -> type:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            gaps_count = None
            ret_type = None

            try:
                start = int(start)
                end = int(end)
                gap = int(gap)

                gaps_count = int((end - start) / gap)
                ret_type = int
            except ValueError:
                pass

            if not gaps_count:
                try:
                    t_gap = gap.strip('+').strip('-')

                    parsed_start = dm(self.datastore.to_pydatemath(start)).int_timestamp
                    parsed_end = dm(self.datastore.to_pydatemath(end)).int_timestamp
                    parsed_gap = dm(self.datastore.to_pydatemath(f"+{t_gap}")).int_timestamp - dm('now').int_timestamp

                    gaps_count = int((parsed_end - parsed_start) / parsed_gap)
                    ret_type = str
                except (DateMathException, AttributeError):
                    pass

            if gaps_count is None:
                raise SearchException(
                    "Could not parse histogram ranges. Either you've mix integer and dates values or you "
                    "have invalid date math values. (start='%s', end='%s', gap='%s')" % (start, end, gap))

            if gaps_count > self.MAX_HISTOGRAM_STEPS:
                raise SearchException(f'Histograms are limited to a maximum of {self.MAX_HISTOGRAM_STEPS} steps. '
                                      f'Current settings would generate {gaps_count} steps')
            return ret_type

    def histogram(self, field, start, end, gap, query="id:*", mincount=1, filters=None, access_control=None,
                  index_type=Index.HOT, key_space=None):
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
            ('histogram_gap', gap.strip('+').strip('-') if isinstance(gap, str) else gap),
            ('histogram_mincount', mincount),
            ('histogram_start', start),
            ('histogram_end', end),
            ('df', self.DEFAULT_SEARCH_FIELD)
        ]

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        result = self._search(args, index_type=index_type, key_space=key_space)

        # Convert the histogram into a dictionary
        return {type_modifier(row.get('key_as_string', row['key'])): row['doc_count']
                for row in result['aggregations']['histogram']['buckets']}

    def facet(self, field, query="id:*", mincount=1, filters=None, access_control=None, index_type=Index.HOT,
              field_script=None, key_space=None):
        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('facet_active', True),
            ('facet_fields', [field]),
            ('facet_mincount', mincount),
            ('rows', 0),
            ('df', self.DEFAULT_SEARCH_FIELD)
        ]

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        if field_script:
            args.append(('field_script', field_script))

        result = self._search(args, index_type=index_type, key_space=key_space)

        # Convert the histogram into a dictionary
        return {row.get('key_as_string', row['key']): row['doc_count']
                for row in result['aggregations'][field]['buckets']}

    def stats(self, field, query="id:*", filters=None, access_control=None, index_type=Index.HOT, field_script=None):
        if filters is None:
            filters = []
        elif isinstance(filters, str):
            filters = [filters]

        args = [
            ('query', query),
            ('stats_active', True),
            ('stats_fields', [field]),
            ('rows', 0),
            ('df', self.DEFAULT_SEARCH_FIELD)
        ]

        if access_control:
            filters.append(access_control)

        if filters:
            args.append(('filters', filters))

        if field_script:
            args.append(('field_script', field_script))

        result = self._search(args, index_type=index_type)
        return result['aggregations'][f"{field}_stats"]

    def grouped_search(self, group_field, query="id:*", offset=0, sort=None, group_sort=None, fl=None, limit=1,
                       rows=None, filters=None, access_control=None, as_obj=True, index_type=Index.HOT,
                       track_total_hits=None):
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
            ('sort', sort),
            ('df', self.DEFAULT_SEARCH_FIELD)
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

        result = self._search(args, index_type=index_type, track_total_hits=track_total_hits)

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
        """
        This function should return all the fields in the index with their types

        :return:
        """

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

        data = self.with_retries(self.datastore.client.indices.get, index=self.name)
        idx_name = list(data.keys())[0]
        properties = flatten_fields(data[idx_name]['mappings'].get('properties', {}))

        if self.model_class:
            model_fields = self.model_class.flat_fields()
        else:
            model_fields = {}

        collection_data = {}

        for p_name, p_val in properties.items():
            if p_name.startswith("_") or "//" in p_name:
                continue
            if not self.FIELD_SANITIZER.match(p_name):
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

    def _get_index_settings(self, archive=False) -> dict:
        default_stub: dict = deepcopy(default_index)
        settings: dict = default_stub.pop('settings', {})

        if 'index' not in settings:
            settings['index'] = {}
        settings['index']['number_of_shards'] = self.shards if not archive else self.archive_shards
        settings['index']['number_of_replicas'] = self.replicas if not archive else self.archive_replicas
        return settings

    def _get_index_mappings(self) -> dict:
        mappings: dict = deepcopy(default_mapping)
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

        return mappings

    def __get_possible_fields(self, field):
        field_types = [field.__name__.lower()]
        if field.__bases__[0] != _Field:
            field_types.extend(self.__get_possible_fields(field.__bases__[0]))

        return field_types

    def _check_fields(self, model=None):
        if not self.validate:
            return

        if model is None:
            if self.model_class:
                return self._check_fields(self.model_class)
            return

        fields = self.fields()
        model = self.model_class.flat_fields(skip_mappings=True)

        missing = set(model.keys()) - set(fields.keys())
        if missing:
            self._add_fields({key: model[key] for key in missing})

        matching = set(fields.keys()) & set(model.keys())
        for field_name in matching:
            if fields[field_name]['indexed'] != model[field_name].index and model[field_name].index:
                raise RuntimeError(f"Field {field_name} should be indexed but is not.")

            possible_field_types = self.__get_possible_fields(model[field_name].__class__)

            if fields[field_name]['type'] not in possible_field_types:
                raise RuntimeError(f"Field {field_name} didn't have the expected store "
                                   f"type. [{fields[field_name]['type']} != "
                                   f"{model[field_name].__class__.__name__.lower()}]")

    def _ensure_collection(self):
        """
        This function should test if the collection that you are trying to access does indeed exist
        and should create it if it does not.

        :return:
        """
        for alias in self.get_index_list(None):
            index = f"{alias}_hot"
            # Create HOT index
            if not self.with_retries(self.datastore.client.indices.exists, index=alias):
                log.debug(f"Index {alias.upper()} does not exists. Creating it now...")
                try:
                    self.with_retries(self.datastore.client.indices.create, index=index,
                                      mappings=self._get_index_mappings(),
                                      settings=self._get_index_settings(archive=self.is_archive_index(index)))
                except elasticsearch.exceptions.RequestError as e:
                    if "resource_already_exists_exception" not in str(e):
                        raise
                    log.warning(f"Tried to create an index template that already exists: {alias.upper()}")

                self.with_retries(self.datastore.client.indices.put_alias, index=index, name=alias)
            elif not self.with_retries(self.datastore.client.indices.exists, index=index) and \
                    not self.with_retries(self.datastore.client.indices.exists_alias, name=alias):
                # Turn on write block
                self.with_retries(self.datastore.client.indices.put_settings,
                                  index=alias, settings=write_block_settings)

                # Create a copy on the result index
                self._safe_index_copy(self.datastore.client.indices.clone, alias, index)

                # Make the hot index the new clone
                actions = [{"add":  {"index": index, "alias": alias}}, {
                    "remove_index": {"index": alias}}]
                self.with_retries(self.datastore.client.indices.update_aliases, actions=actions)

                self.with_retries(self.datastore.client.indices.put_settings,
                                  index=alias, settings=write_unblock_settings)

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
        for index in self.get_index_list(None):
            self.with_retries(self.datastore.client.indices.put_mapping, index=index, properties=properties)

    def wipe(self, recreate=True, index_type=None):
        """
        This function should completely delete the collection

        NEVER USE THIS!

        :return:
        """

        for name in self.get_index_list(index_type):
            index = f"{name}_hot"
            log.debug("Wipe operation started for collection: %s" % name.upper())
            if self.with_retries(self.datastore.client.indices.exists, index=index):
                self.with_retries(self.datastore.client.indices.delete, index=index)

        if recreate:
            self._ensure_collection()
