import concurrent.futures
import logging
import re
import warnings

from datemath import dm
from datemath.helpers import DateMathException

from assemblyline.datastore.exceptions import DataStoreException, UndefinedFunction, SearchException
from assemblyline.odm import BANNED_FIELDS
from assemblyline.remote.datatypes.lock import Lock

log = logging.getLogger('assemblyline.datastore')


def get_object(base, key):
    splitted = key.split(".", 1)
    if len(splitted) == 1:
        return base, key
    else:
        current, child = splitted
        return get_object(base[current], child)


class Collection(object):
    RETRY_NORMAL = 1
    RETRY_NONE = 0
    RETRY_INFINITY = -1
    DEFAULT_ROW_SIZE = 25
    FIELD_SANITIZER = re.compile("^[a-z][a-z0-9_\\-.]+$")
    MAX_FACET_LIMIT = 100
    MAX_RETRY_BACKOFF = 10
    UPDATE_SET = "SET"
    UPDATE_INC = "INC"
    UPDATE_DEC = "DEC"
    UPDATE_APPEND = "APPEND"
    UPDATE_REMOVE = "REMOVE"
    UPDATE_OPERATIONS = [
        UPDATE_APPEND,
        UPDATE_DEC,
        UPDATE_INC,
        UPDATE_REMOVE,
        UPDATE_SET
    ]

    def __init__(self, datastore, name, model_class=None):
        self.datastore = datastore
        self.name = name
        self.model_class = model_class
        self._ensure_collection()

    def with_retries(self, func, *args, **kwargs):
        """
        This function performs the passed function with the given args and kwargs and reconnect if it fails

        :return: return the output of the function passed
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def normalize(self, data, as_obj=True):
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

    def commit(self):
        """
        This function should be overloaded to perform a commit of the index data of all the different hosts
        specified in self.datastore.hosts.

        :return: Should return True of the commit was successful on all hosts
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    def multiget(self, key_list, as_dictionary=True, as_obj=True):
        """
        Get a list of documents from the datastore and make sure they are normalized using
        the model class

        :param as_dictionary:
        :param as_obj:
        :param key_list: list of keys of documents to get
        :return: list of instances of the model class
        """
        if as_dictionary:
            return {x: self.get(x, as_obj=as_obj) for x in key_list}
        else:
            return [self.get(x, as_obj=as_obj) for x in key_list]

    def _get(self, key, retries):
        """
        This function should be overloaded in a way that if the document is not found,
        the function retries to get the document the specified amount of time.

        retries = -1 means that we will retry forever.

        :param key: key of the document to get from the datastore
        :param retries: number of time to retry if the document can't be found
        :return: The document strait of the datastore
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def get(self, key, as_obj=True):
        """
        Get a document from the datastore, retry a few times if not found and normalize the
        document with the model provided with the collection.

        This is the normal way to get data of the system.

        :param as_obj:
        :param key: key of the document to get from the datastore
        :return: an instance of the model class loaded with the document data
        """
        return self.normalize(self._get(key, self.RETRY_NORMAL), as_obj=as_obj)

    def get_if_exists(self, key, as_obj=True):
        """
        Get a document from the datastore but do not retry if not found.

        Use this more in caching scenarios because eventually consistent database may lead
        to have document reported has missing even if they exist.

        :param as_obj:
        :param key: key of the document to get from the datastore
        :return: an instance of the model class loaded with the document data
        """
        return self.normalize(self._get(key, self.RETRY_NONE), as_obj=as_obj)

    def require(self, key, as_obj=True):
        """
        Get a document from the datastore and retry forever because we know for sure
        that this document should exist. If it does not right now, this will wait for the
        document to show up in the datastore.

        :param as_obj:
        :param key: key of the document to get from the datastore
        :return: an instance of the model class loaded with the document data
        """
        return self.normalize(self._get(key, self.RETRY_INFINITY), as_obj=as_obj)

    def save(self, key, data):
        """
        Save a to document to the datastore using the key as its document id.

        The document data will be normalized before being saved in the datastore.

        :param key: ID of the document to save
        :param data: raw data or instance of the model class to save as the document
        :return: True if the document was saved properly
        """
        return self._save(key, self.normalize(data))

    def _save(self, key, data):
        """
        This function should takes in an instance of the the model class as input
        and saves it to the database backend at the id mentioned by the key.

        This function should return True if the data was saved correctly

        :param key: key to use to store the document
        :param data: instance of the model class to save to the database
        :return: True if save was successful
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

    def delete_matching(self, query):
        """
        This function should delete the underlying documents referenced by the query.
        It should return true if the documents were in fact properly deleted.

        :param query: Query of the documents to download
        :return: True is delete successful
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def _validate_operations(self, operations):
        """
        Validate the different operations received for a partial update

        :param operations: list of operation tuples
        :raises: DatastoreException if operation not valid
        """
        if self.model_class:
            fields = self.model_class.flat_fields()
        else:
            fields = None

        for op, doc_key, value in operations:
            if op not in self.UPDATE_OPERATIONS:
                raise DataStoreException(f"Not a valid Update Operation: {op}")

            if fields is not None:
                if doc_key not in fields:
                    raise DataStoreException(f"Invalid field for model: {doc_key}")

                field = fields[doc_key]
                if op in [self.UPDATE_APPEND, self.UPDATE_REMOVE]:
                    try:
                        if value != field.check(value):
                            raise DataStoreException(f"Invalid value for field {doc_key}: {value}")
                    except (ValueError, TypeError, AttributeError):
                        raise DataStoreException(f"Invalid value for field {doc_key}: {value}")

                elif op in [self.UPDATE_SET, self.UPDATE_DEC, self.UPDATE_INC]:
                    try:
                        if value != field.check(value):
                            raise DataStoreException(f"Invalid value for field {doc_key}: {value}")
                    except (ValueError, TypeError):
                        raise DataStoreException(f"Invalid value for field {doc_key}: {value}")

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
        self._validate_operations(operations)
        return self._update(key, operations)

    def update_by_query(self, query, operations, filters=None, access_control=None):
        """
        This function performs an atomic update on some fields from the
        underlying documents matching the query and the filters using a list of operations.

        Operations supported by the update function are the following:
        INTEGER ONLY: Increase and decreased value
        LISTS ONLY: Append and remove items
        ALL TYPES: Set value

        :param filters: Filter queries to reduce the data
        :param query: Query to find the matching documents
        :param operations: List of tuple of operations e.q. [(SET, document_key, operation_value), ...]
        :return: True is update successful
        """
        self._validate_operations(operations)
        if access_control:
            if filters is None:
                filters = []
            filters.append(access_control)
        return self._update_by_query(query, operations, filters=filters)

    def _update_by_query(self, query, operations, filters):
        with concurrent.futures.ThreadPoolExecutor(20) as executor:
            res = {item[self.datastore.ID][0]: executor.submit(self._update, item[self.datastore.ID][0], operations)
                   for item in self.stream_search(query, fl=self.datastore.ID, filters=filters, as_obj=False)}
        for k, v in res.items():
            if not v.result():
                return False
        return True

    def _update(self, key, operations):
        with Lock(f'collection-{self.name}-update-{key}', 5):
            data = self.get(key)

            for op, doc_key, value in operations:
                obj, cur_key = get_object(data, doc_key)
                if op == self.UPDATE_SET:
                    obj[cur_key] = value
                elif op == self.UPDATE_APPEND:
                    obj[cur_key].append(value)
                elif op == self.UPDATE_REMOVE:
                    obj[cur_key].remove(value)
                elif op == self.UPDATE_INC:
                    obj[cur_key] += value
                elif op == self.UPDATE_DEC:
                    obj[cur_key] -= value

            return self.save(key, data)

    def search(self, query, offset=0, rows=DEFAULT_ROW_SIZE, sort=None, fl=None, timeout=None,
               filters=(), access_control=None, as_obj=True):
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

    def stream_search(self, query, fl=None, filters=(), access_control=None, buffer_size=200, as_obj=True):
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
        for item in self.stream_search("%s:*" % self.datastore.ID, fl=self.datastore.ID, access_control=access_control):
            try:
                yield item.id
            except AttributeError:
                value = item[self.datastore.ID]
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
                try:
                    parsed_start = dm(self.datastore.to_pydatemath(start)).timestamp
                    parsed_end = dm(self.datastore.to_pydatemath(end)).timestamp
                    parsed_gap = dm(self.datastore.to_pydatemath(gap)).timestamp - dm('now').timestamp

                    gaps_count = int((parsed_end - parsed_start) / parsed_gap)
                    ret_type = str
                except DateMathException:
                    pass

            if not gaps_count:
                raise SearchException(
                    "Could not parse date ranges. (start='%s', end='%s', gap='%s')" % (start, end, gap))

            if gaps_count > self.MAX_FACET_LIMIT:
                raise SearchException('Facet max steps are limited to %s. '
                                      'Current settings would generate %s steps' % (self.MAX_FACET_LIMIT,
                                                                                    gaps_count))
            return ret_type

    def histogram(self, field, start, end, gap, query="*", mincount=1, filters=(), access_control=None):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def field_analysis(self, field, query="*", prefix=None, contains=None, ignore_case=False, sort=None, limit=10,
                       min_count=1, filters=(), access_control=None):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def grouped_search(self, group_field, query="*", offset=None, sort=None, group_sort=None, fl=None, limit=None,
                       rows=DEFAULT_ROW_SIZE, filters=(), access_control=None, as_obj=True):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    def fields(self):
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

    def _check_fields(self, model=None):
        if model is None:
            if self.model_class:
                return self._check_fields(self.model_class)
            return

        fields = self.fields()
        model = self.model_class.flat_fields(skip_mappings=True)

        missing = set(model.keys()) - set(fields.keys())
        if missing:
            raise RuntimeError(f"Couldn't load collection, fields missing: {missing}")

        matching = set(fields.keys()) & set(model.keys())
        for field_name in matching:
            if fields[field_name]['indexed'] != model[field_name].index:
                raise RuntimeError(f"Field {field_name} didn't have the expected indexing value.")
            if fields[field_name]['stored'] != model[field_name].store:
                raise RuntimeError(f"Field {field_name} didn't have the expected store value.")

            possible_field_types = [
                model[field_name].__class__.__name__.lower(),
                model[field_name].__class__.__bases__[0].__name__.lower(),
            ]
            if fields[field_name]['type'] not in possible_field_types:
                raise RuntimeError(f"Field {field_name} didn't have the expected store "
                                   f"type. [{fields[field_name]['type']} != "
                                   f"{model[field_name].__class__.__name__.lower()}]")

    def wipe(self):
        """
        This function should completely delete the collection

        NEVER USE THIS!

        :return:
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")


class BaseStore(object):
    ID = None
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

    def __init__(self, hosts, collection_class):
        self._hosts = hosts
        self._collection_class = collection_class
        self._closed = False
        self._collections = {}
        self._models = {}

    def __enter__(self):
        return self

    # noinspection PyUnusedLocal
    def __exit__(self, ex_type, exc_val, exc_tb):
        self.close()

    def __str__(self):
        return '{0}'.format(self.__class__.__name__)

    def __getattr__(self, name) -> Collection:
        if name not in self._collections:
            model_class = self._models[name]
            self._collections[name] = self._collection_class(self, name, model_class=model_class)

        return self._collections[name]

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

    def get_hosts(self):
        return self._hosts

    def close(self):
        self._closed = True

    def connection_reset(self):
        raise UndefinedFunction("This is the basic datastore object, connection_reset method is undefined.")

    def ping(self):
        raise UndefinedFunction("This is the basic datastore object, ping method is undefined.")

    def is_closed(self):
        return self._closed

    def register(self, name, model_class=None):
        if re.match(r'[a-z0-9_]*', name).string != name:
            raise DataStoreException('Invalid characters in model name. '
                                     'You can only use lower case letters, numbers and underscores.')

        self._models[name] = model_class
