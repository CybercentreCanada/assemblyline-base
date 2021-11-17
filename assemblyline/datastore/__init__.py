from __future__ import annotations
import concurrent.futures
import logging
import re
from typing import Any, Iterable, Union, Generic, TypeVar
import warnings

from datemath import dm
from datemath.helpers import DateMathException
from datetime import datetime
from urllib.parse import urlparse

from assemblyline.datastore.exceptions import DataStoreException, UndefinedFunction, SearchException, MultiKeyError
from assemblyline.odm import BANNED_FIELDS, Keyword, Integer, List, Mapping, Model, ClassificationObject
from assemblyline.odm.base import _Field
from assemblyline.remote.datatypes.lock import Lock

log = logging.getLogger('assemblyline.datastore')


def get_object(base, key):
    splitted = key.split(".", 1)
    if len(splitted) == 1:
        return base, key
    else:
        current, child = splitted
        return get_object(base[current], child)


class BulkPlan(object):
    def __init__(self, indexes, model=None):
        self.indexes = indexes
        self.model = model
        self.operations = []

    def add_delete_operation(self, doc_id, index=None):
        raise UndefinedFunction("This is the basic BulkPlan object, none of the methods are defined.")

    def add_insert_operation(self, doc_id, doc, index=None):
        raise UndefinedFunction("This is the basic BulkPlan object, none of the methods are defined.")

    def add_upsert_operation(self, doc_id, doc, index=None):
        raise UndefinedFunction("This is the basic BulkPlan object, none of the methods are defined.")

    def add_update_operation(self, doc_id, doc, index=None):
        raise UndefinedFunction("This is the basic BulkPlan object, none of the methods are defined.")

    def get_plan_data(self):
        raise UndefinedFunction("This is the basic BulkPlan object, none of the methods are defined.")

    @property
    def empty(self):
        return len(self.operations) == 0


ModelType = TypeVar('ModelType', bound=Model)


class Collection(Generic[ModelType]):
    DEFAULT_ROW_SIZE = 25
    DEFAULT_SEARCH_FIELD = '__text__'
    FIELD_SANITIZER = re.compile("^[a-z][a-z0-9_\\-.]+$")
    MAX_FACET_LIMIT = 100
    MAX_RETRY_BACKOFF = 10
    RETRY_NORMAL = 1
    RETRY_NONE = 0
    RETRY_INFINITY = -1
    UPDATE_SET = "SET"
    UPDATE_INC = "INC"
    UPDATE_DEC = "DEC"
    UPDATE_APPEND = "APPEND"
    UPDATE_REMOVE = "REMOVE"
    UPDATE_DELETE = "DELETE"
    UPDATE_OPERATIONS = [
        UPDATE_APPEND,
        UPDATE_DEC,
        UPDATE_INC,
        UPDATE_REMOVE,
        UPDATE_SET,
        UPDATE_DELETE,
    ]

    def __init__(self, datastore, name, model_class=None, validate=True):
        self.datastore = datastore
        self.name = name
        self.index_name = f"{name}_hot"
        self.model_class = model_class
        self.validate = validate
        self.bulk_plan_class = BulkPlan
        self._ensure_collection()

    @staticmethod
    def _get_obj_value(obj, field):
        value = obj[field]
        if isinstance(value, list):
            return value[0]
        return value

    @property
    def index_list(self):
        """
        This property contains the list of valid indexes for the current collection.

        :return: list of valid indexes for this collection
        """
        return [self.name]

    def with_retries(self, func, *args, **kwargs):
        """
        This function performs the passed function with the given args and kwargs and reconnect if it fails

        :return: return the output of the function passed
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def normalize(self, data, as_obj=True) -> Union[ModelType, dict[str, Any], None]:
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

    def _bulk(self, operations):
        """
        This function should be overloaded to perform a bulk operations on the datastore.

        :return: Results of the bulk operation
        """

        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def bulk(self, operations):
        """
        Receives a bulk plan and executes the plan.

        :return: Results of the bulk operation
        """

        if not isinstance(operations, BulkPlan):
            return TypeError("Operations must be of type BulkPlan")

        return self._bulk(operations.get_plan_data())

    def get_bulk_plan(self):
        """
        Creates a BulkPlan tailored for the current datastore

        :return: The BulkPlan object
        """
        return self.bulk_plan_class(self.index_list, model=self.model_class)

    def commit(self):
        """
        This function should be overloaded to perform a commit of the index data of all the different hosts
        specified in self.datastore.hosts.

        :return: Should return True of the commit was successful on all hosts
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def fix_ilm(self):
        """
        This function should be overloaded to fix the ILM configuration of the index of all the different hosts
        specified in self.datastore.hosts.

        :return: Should return True of the fix was successful on all hosts
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def fix_replicas(self):
        """
        This function should be overloaded to fix the replica configuration of the index of all the different hosts
        specified in self.datastore.hosts.

        :return: Should return True of the fix was successful on all hosts
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def fix_shards(self):
        """
        This function should be overloaded to fix the shard configuration of the index of all the different hosts
        specified in self.datastore.hosts.

        :return: Should return True of the fix was successful on all hosts
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def reindex(self):
        """
        This function should be overloaded to perform a reindex of all the data of the different hosts
        specified in self.datastore.hosts.

        :return: Should return True of the commit was successful on all hosts
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def multiget(self, key_list, as_dictionary=True, as_obj=True, error_on_missing=True):
        """
        Get a list of documents from the datastore and make sure they are normalized using
        the model class

        :param error_on_missing: Should it raise a key error when keys are missing
        :param as_dictionary: Return a disctionary of items or a list
        :param as_obj: Return objects or not
        :param key_list: list of keys of documents to get
        :return: list of instances of the model class
        """
        missing = []

        if as_dictionary:
            output = {}
            for x in key_list:
                item = self.get(x, as_obj=as_obj)
                if item is None:
                    missing.append(x)
                else:
                    output[x] = item
        else:
            output = []
            for x in key_list:
                item = self.get(x, as_obj=as_obj)
                if item is None:
                    missing.append(x)
                else:
                    output.append(item)

        if error_on_missing and missing:
            raise MultiKeyError(missing, output)

        return output

    def exists(self, key, force_archive_access=False) -> bool:
        """
        Check if a document exists in the datastore.

        :param force_archive_access: Temporary force access to archive during this call
        :param key: key of the document to get from the datastore
        :return: true/false depending if the document exists or not
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def _get(self, key, retries, force_archive_access=False, version=False) -> Any:
        """
        This function should be overloaded in a way that if the document is not found,
        the function retries to get the document the specified amount of time.

        retries = -1 means that we will retry forever.

        :param key: key of the document to get from the datastore
        :param retries: number of time to retry if the document can't be found
        :param version: should the version number be returned by the call
        :return: The document strait of the datastore
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def get(self, key, as_obj=True, force_archive_access=False, version=False):
        """
        Get a document from the datastore, retry a few times if not found and normalize the
        document with the model provided with the collection.

        This is the normal way to get data of the system.

        :param force_archive_access: Temporary force access to archive during this call
        :param as_obj: Should the data be returned as an ODM object
        :param key: key of the document to get from the datastore
        :param version: should the version number be returned by the call
        :return: an instance of the model class loaded with the document data
        """
        data = self._get(key, self.RETRY_NORMAL, force_archive_access=force_archive_access, version=version)
        if version:
            data, version = data
            return self.normalize(data, as_obj=as_obj), version
        return self.normalize(data, as_obj=as_obj)

    def get_if_exists(self, key, as_obj=True, force_archive_access=False, version=False):
        """
        Get a document from the datastore but do not retry if not found.

        Use this more in caching scenarios because eventually consistent database may lead
        to have document reported has missing even if they exist.

        :param force_archive_access: Temporary force access to archive during this call
        :param as_obj: Should the data be returned as an ODM object
        :param key: key of the document to get from the datastore
        :param version: should the version number be returned by the call
        :return: an instance of the model class loaded with the document data
        """
        data = self._get(key, self.RETRY_NONE, force_archive_access=force_archive_access, version=version)
        if version:
            data, version = data
            return self.normalize(data, as_obj=as_obj), version
        return self.normalize(data, as_obj=as_obj)

    def require(self, key, as_obj=True, force_archive_access=False, version=False) -> Union[dict[str, Any], ModelType]:
        """
        Get a document from the datastore and retry forever because we know for sure
        that this document should exist. If it does not right now, this will wait for the
        document to show up in the datastore.

        :param force_archive_access: Temporary force access to archive during this call
        :param as_obj: Should the data be returned as an ODM object
        :param key: key of the document to get from the datastore
        :param version: should the version number be returned by the call
        :return: an instance of the model class loaded with the document data
        """
        data = self._get(key, self.RETRY_INFINITY, force_archive_access=force_archive_access, version=version)
        if version:
            data, version = data
            return self.normalize(data, as_obj=as_obj), version
        return self.normalize(data, as_obj=as_obj)

    def save(self, key, data, version=None):
        """
        Save a to document to the datastore using the key as its document id.

        The document data will be normalized before being saved in the datastore.

        :param force_archive_access: Temporary force access to archive during this call
        :param key: ID of the document to save
        :param data: raw data or instance of the model class to save as the document
        :param version: version of the document to save over, if the version check fails this will raise an exception
        :return: True if the document was saved properly
        """
        if " " in key:
            raise DataStoreException("You are not allowed to use spaces in datastore keys.")

        return self._save(key, self.normalize(data), version=version)

    def _save(self, key, data, version=None):
        """
        This function should takes in an instance of the the model class as input
        and saves it to the database backend at the id mentioned by the key.

        This function should return True if the data was saved correctly

        :param force_archive_access: Temporary force access to archive during this call
        :param key: key to use to store the document
        :param data: instance of the model class to save to the database
        :param version: version of the document to save over, if the version check fails this will raise an exception
        :return: True if save was successful
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def archive(self, query):
        """
        This function should archive to document that are matching to query to an time splitted index

        :param query: query to run to archive documents
        :return: Number of archived documents
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def delete(self, key):
        """
        This function should delete the underlying document referenced by the key.
        It should return true if the document was in fact properly deleted.

        :param key: id of the document to delete
        :return: True is delete successful
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def delete_by_query(self, query, workers=20, max_docs=None):
        """
        This function should delete the underlying documents referenced by the query.
        It should return true if the documents were in fact properly deleted.

        :param query: Query of the documents to download
        :param workers: Number of workers used for deletion if basic currency delete is used
        :return: True is delete successful
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

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

                if op in [self.UPDATE_APPEND, self.UPDATE_REMOVE]:
                    try:
                        value = field.check(value)
                    except (ValueError, TypeError, AttributeError):
                        raise DataStoreException(f"Invalid value for field {doc_key}: {value}")

                elif op in [self.UPDATE_SET, self.UPDATE_DEC, self.UPDATE_INC]:
                    try:
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

    def update(self, key, operations):
        """
        This function performs an atomic update on some fields from the
        underlying documents referenced by the id using a list of operations.

        Operations supported by the update function are the following:
        INTEGER ONLY: Increase and decreased value
        LISTS ONLY: Append and remove items
        ALL TYPES: Set value

        :param key: ID of the document to modify
        :param operations: List of tuple of operations e.q. [(SET, document_key, operation_value), ...]
        :return: True is update successful
        """
        operations = self._validate_operations(operations)
        return self._update(key, operations)

    def update_by_query(self, query, operations, filters=None, access_control=None, max_docs=None):
        """
        This function performs an atomic update on some fields from the
        underlying documents matching the query and the filters using a list of operations.

        Operations supported by the update function are the following:
        INTEGER ONLY: Increase and decreased value
        LISTS ONLY: Append and remove items
        ALL TYPES: Set value

        :param access_control:
        :param filters: Filter queries to reduce the data
        :param query: Query to find the matching documents
        :param operations: List of tuple of operations e.q. [(SET, document_key, operation_value), ...]
        :return: True is update successful
        """
        operations = self._validate_operations(operations)
        if access_control:
            if filters is None:
                filters = []
            filters.append(access_control)
        return self._update_by_query(query, operations, filters=filters, max_docs=max_docs)

    def _update_by_query(self, query, operations, filters, max_docs=None):
        with concurrent.futures.ThreadPoolExecutor(20) as executor:
            res = {self._get_obj_value(item, 'id'): executor.submit(self._update, self._get_obj_value(item, 'id'),
                                                                    operations)
                   for item in self.stream_search(query, fl='id', filters=filters, as_obj=False)}
        count = 0
        for k, v in res.items():
            count += 1
            v.result()

        return count

    def _update(self, key, operations):
        with Lock(f'collection-{self.name}-update-{key}', 5):
            data = self.get(key, as_obj=False)

            for op, doc_key, value in operations:
                obj, cur_key = get_object(data, doc_key)
                if op == self.UPDATE_SET:
                    obj[cur_key] = value
                elif op == self.UPDATE_DELETE:
                    obj[cur_key].pop(value)
                elif op == self.UPDATE_APPEND:
                    obj[cur_key].append(value)
                elif op == self.UPDATE_REMOVE:
                    obj[cur_key].remove(value)
                elif op == self.UPDATE_INC:
                    obj[cur_key] += value
                elif op == self.UPDATE_DEC:
                    obj[cur_key] -= value

            return self._save(key, data)

    def search(self, query, offset=0, rows=DEFAULT_ROW_SIZE, sort=None, fl=None, timeout=None,
               filters=(), access_control=None, deep_paging_id=None, as_obj=True, use_archive=False,
               track_total_hits=False) -> dict:
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

        :param track_total_hits: Return to total matching document count
        :param use_archive: Query also the archive
        :param deep_paging_id: ID of the next page during deep paging searches
        :param as_obj: Return objects instead of dictionaries
        :param query: lucene query to search for
        :param offset: offset at which you want the results to start at (paging)
        :param rows: number of items that the search function should return
        :param sort: field to sort the data with
        :param fl: list of fields to return from the search
        :param timeout: maximum time of execution
        :param filters: additional queries to run on the original query to reduce the scope
        :param access_control: access control parameters to limiti the scope of the query
        :return: a search result object
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def stream_search(self, query, fl=None, filters=(), access_control=None, item_buffer_size=200,
                      as_obj=True, use_archive=False) -> Iterable[Union[dict[str, Any], ModelType]]:
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

        :param use_archive: Query also the archive
        :param as_obj: Return objects instead of dictionaries
        :param query: lucene query to search for
        :param fl: list of fields to return from the search
        :param filters: additional queries to run on the original query to reduce the scope
        :param access_control: access control parameters to run the query with
        :param buffer_size: number of items to buffer with each search call
        :return: a generator of dictionary of field list results
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def keys(self, access_control=None):
        """
        This function streams the keys of all the documents of this collection.

        :param access_control: access control parameter to limit the scope of the key scan
        :return: a generator of keys
        """
        for item in self.stream_search("id:*", fl='id', access_control=access_control):
            try:
                yield item.id
            except AttributeError:
                value = item['id']
                if isinstance(value, list):
                    for v in value:
                        yield v
                else:
                    yield value

    # noinspection PyBroadException
    def _validate_steps_count(self, start, end, gap):
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
                if not (gap.startswith("-") or gap.startswith("+")):
                    raise SearchException("Gap must be preceded with either + or - sign.")

                try:
                    parsed_start = dm(self.datastore.to_pydatemath(start)).int_timestamp
                    parsed_end = dm(self.datastore.to_pydatemath(end)).int_timestamp
                    parsed_gap = dm(self.datastore.to_pydatemath(gap)).int_timestamp - dm('now').int_timestamp

                    gaps_count = int((parsed_end - parsed_start) / parsed_gap)
                    ret_type = str
                except (DateMathException, AttributeError):
                    pass

            if not gaps_count:
                raise SearchException(
                    "Could not parse date ranges. (start='%s', end='%s', gap='%s')" % (start, end, gap))

            if gaps_count > self.MAX_FACET_LIMIT:
                raise SearchException(f'Histograms are limited to a maximum of {self.MAX_FACET_LIMIT} steps. '
                                      f'Current settings would generate {gaps_count} steps')
            return ret_type

    def histogram(self, field, start, end, gap, query="id:*", mincount=1,
                  filters=None, access_control=None, use_archive=False) -> dict[str, int]:
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def facet(self, field, query="id:*", prefix=None, contains=None, ignore_case=False, sort=None, limit=10,
              mincount=1, filters=None, access_control=None, use_archive=False) -> dict[str, int]:
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def stats(self, field, query="id:*", filters=None, access_control=None, use_archive=False):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def grouped_search(self, group_field, query="id:*", offset=None, sort=None, group_sort=None, fl=None, limit=None,
                       rows=DEFAULT_ROW_SIZE, filters=(), access_control=None, as_obj=True, use_archive=False,
                       track_total_hits=False):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def fields(self) -> dict:
        """
        This function should return all the fields in the index with their types

        :return:
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def _ensure_collection(self):
        """
        This function should test if the collection that you are trying to access does indeed exist
        and should create it if it does not.

        :return:
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

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
            if fields[field_name]['stored'] != model[field_name].store and model[field_name].store:
                raise RuntimeError(f"Field {field_name} should be stored but is not.")

            possible_field_types = self.__get_possible_fields(model[field_name].__class__)

            if fields[field_name]['type'] not in possible_field_types:
                raise RuntimeError(f"Field {field_name} didn't have the expected store "
                                   f"type. [{fields[field_name]['type']} != "
                                   f"{model[field_name].__class__.__name__.lower()}]")

    def _add_fields(self, missing_fields: dict[str, _Field]):
        raise RuntimeError(f"Couldn't load collection, fields missing: {missing_fields.keys()}")

    def wipe(self):
        """
        This function should completely delete the collection

        NEVER USE THIS!

        :return:
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")


class BaseStore(object):
    ID = 'id'
    DEFAULT_SORT = None
    DATE_FORMAT = {
        'NOW': None,
        'YEAR': None,
        'MONTH': None,
        'WEEK': None,
        'DAY': None,
        'HOUR': None,
        'MINUTE': None,
        'SECOND': None,
        'MILLISECOND': None,
        'MICROSECOND': None,
        'NANOSECOND': None,
        'SEPARATOR': None,
        'DATE_END': None
    }

    DATEMATH_MAP = {
        'NOW': 'now',
        'YEAR': 'y',
        'MONTH': 'M',
        'WEEK': 'w',
        'DAY': 'd',
        'HOUR': 'h',
        'MINUTE': 'm',
        'SECOND': 's',
        'DATE_END': 'Z||'
    }

    def __init__(self, hosts, collection_class, ilm_config=None):
        self._hosts = hosts
        self._collection_class = collection_class
        self._closed = False
        self._collections = {}
        self._models = {}
        self.ilm_config = ilm_config
        self.validate = True

    def __enter__(self):
        return self

    # noinspection PyUnusedLocal
    def __exit__(self, ex_type, exc_val, exc_tb):
        self.close()

    def __str__(self):
        return '{0}'.format(self.__class__.__name__)

    def __getattr__(self, name) -> Collection:
        if not self.validate:
            return self._collection_class(self, name, model_class=self._models[name], validate=self.validate)

        if name not in self._collections:
            self._collections[name] = self._collection_class(
                self, name, model_class=self._models[name], validate=self.validate)

        return self._collections[name]

    def get_models(self):
        return self._models

    def to_pydatemath(self, value):
        replace_list = [
            (self.now, self.DATEMATH_MAP['NOW']),
            (self.year, self.DATEMATH_MAP['YEAR']),
            (self.month, self.DATEMATH_MAP['MONTH']),
            (self.week, self.DATEMATH_MAP['WEEK']),
            (self.day, self.DATEMATH_MAP['DAY']),
            (self.hour, self.DATEMATH_MAP['HOUR']),
            (self.minute, self.DATEMATH_MAP['MINUTE']),
            (self.second, self.DATEMATH_MAP['SECOND']),
            (self.DATE_FORMAT['DATE_END'], self.DATEMATH_MAP['DATE_END'])
        ]

        for x in replace_list:
            value = value.replace(*x)

        return value

    @property
    def now(self):
        return self.DATE_FORMAT['NOW']

    @property
    def ms(self):
        return self.DATE_FORMAT['MILLISECOND']

    @property
    def us(self):
        return self.DATE_FORMAT['MICROSECOND']

    @property
    def ns(self):
        return self.DATE_FORMAT['NANOSECOND']

    @property
    def year(self):
        return self.DATE_FORMAT['YEAR']

    @property
    def month(self):
        return self.DATE_FORMAT['MONTH']

    @property
    def week(self):
        return self.DATE_FORMAT['WEEK']

    @property
    def day(self):
        return self.DATE_FORMAT['DAY']

    @property
    def hour(self):
        return self.DATE_FORMAT['HOUR']

    @property
    def minute(self):
        return self.DATE_FORMAT['MINUTE']

    @property
    def second(self):
        return self.DATE_FORMAT['SECOND']

    @property
    def date_separator(self):
        return self.DATE_FORMAT['SEPARATOR']

    def get_hosts(self, safe=False):
        if not safe:
            return self._hosts
        else:
            out = []
            for h in self._hosts:
                parsed = urlparse(h)
                out.append(parsed.hostname or parsed.path)
            return out

    def close(self):
        self._closed = True

    def connection_reset(self):
        raise UndefinedFunction("This is the basic datastore object, connection_reset method is undefined.")

    def ping(self):
        raise UndefinedFunction("This is the basic datastore object, ping method is undefined.")

    def is_closed(self):
        return self._closed

    def register(self, name: str, model_class=None):
        if re.match(r'[a-z0-9_]*', name).string != name:
            raise DataStoreException('Invalid characters in model name. '
                                     'You can only use lower case letters, numbers and underscores.')

        self._models[name] = model_class
