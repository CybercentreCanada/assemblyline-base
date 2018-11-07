import logging
import re
import warnings

from datemath import dm
from datemath.helpers import DateMathException

from assemblyline.datastore.exceptions import DataStoreException, UndefinedFunction, SearchException, \
    SearchRetryException
from assemblyline.datastore.reconnect import collection_reconnect

log = logging.getLogger('assemblyline.datastore')


class Collection(object):
    RETRY_NORMAL = 1
    RETRY_NONE = 0
    RETRY_INFINITY = -1
    DEFAULT_ROW_SIZE = 25
    FIELD_SANITIZER = re.compile("^[a-z][a-z0-9_\\-.]+$")
    MAX_FACET_LIMIT = 100

    def __init__(self, datastore, name, model_class=None):
        self.datastore = datastore
        self.name = name
        self.model_class = model_class
        self._ensure_collection()

    def normalize(self, data):
        """
        Normalize the data using the model class

        :param data: data to normalize
        :return: instance of the model class
        """
        if data is not None and self.model_class and not isinstance(data, self.model_class):
            return self.model_class(data)

        return data

    @collection_reconnect(log)
    def commit(self):
        """
        This function should be overloaded to perform a commit of the index data of all the different hosts
        specified in self.datastore.hosts.

        :return: Should return True of the commit was successful on all hosts
        """
        raise UndefinedFunction("This is the basic datastore object, none of the methods are defined.")

    @collection_reconnect(log)
    def multiget(self, key_list):
        """
        Get a list of documents from the datastore and make sure they are normalized using
        the model class

        :param key_list: list of keys of documents to get
        :return: list of instances of the model class
        """
        return [self.get(x) for x in key_list]

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

    @collection_reconnect(log)
    def get(self, key):
        """
        Get a document from the datastore, retry a few times if not found and normalize the
        document with the model provided with the collection.

        This is the normal way to get data of the system.

        :param key: key of the document to get from the datastore
        :return: an instance of the model class loaded with the document data
        """
        return self.normalize(self._get(key, self.RETRY_NORMAL))

    @collection_reconnect(log)
    def get_if_exists(self, key):
        """
        Get a document from the datastore but do not retry if not found.

        Use this more in caching scenarios because eventually consistent database may lead
        to have document reported has missing even if they exist.

        :param key: key of the document to get from the datastore
        :return: an instance of the model class loaded with the document data
        """
        return self.normalize(self._get(key, self.RETRY_NONE))

    @collection_reconnect(log)
    def require(self, key):
        """
        Get a document from the datastore and retry forever because we know for sure
        that this document should exist. If it does not right now, this will wait for the
        document to show up in the datastore.

        :param key: key of the document to get from the datastore
        :return: an instance of the model class loaded with the document data
        """
        return self.normalize(self._get(key, self.RETRY_INFINITY))

    @collection_reconnect(log)
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

    @collection_reconnect(log)
    def delete(self, key):
        """
        This function should delete the underlying document referenced by the key.
        It should return true if the document was in fact properly deleted.

        :param key: id of the document to delete
        :return: True is delete successful
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    @collection_reconnect(log)
    def search(self, query, offset=0, rows=DEFAULT_ROW_SIZE, sort=None, fl=None, timeout=None,
               filters=(), access_control=None):
        """
        This function should perform a search through the datastore and return a
        search result object that consist on the following:

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

    @collection_reconnect(log)
    def stream_search(self, query, fl=None, filters=(), access_control=None, buffer_size=200):
        """
        This function should perform a search through the datastore and stream
        all related results as a dictionary of key value pair where each keys
        are one of the field specified in the field list parameter.

        {
            fl[0]: value,
            ...
            fl[x]: value
        }

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
                yield item[self.datastore.ID]

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

    @collection_reconnect(log)
    def histogram(self, field, start, end, gap, query="*", mincount=1, filters=(), access_control=None):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    @collection_reconnect(log)
    def field_analysis(self, field, query="*", prefix=None, contains=None, ignore_case=False, sort=None, limit=10,
                       min_count=1, filters=(), access_control=None):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    @collection_reconnect(log)
    def grouped_search(self, group_field, query="*", offset=None, sort=None, group_sort=None, fl=None, limit=None,
                       rows=DEFAULT_ROW_SIZE, filters=(), access_control=None):
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    @collection_reconnect(log)
    def fields(self):
        """
        This function should return all the fields in the index with their types

        :return:
        """
        raise UndefinedFunction("This is the basic collection object, none of the methods are defined.")

    @collection_reconnect(log)
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
        model = self.model_class.flat_fields()

        missing = set(model.keys()) - set(fields.keys())
        if missing:
            raise RuntimeError(f"Couldn't load collection, fields missing: {missing}")

        matching = set(fields.keys()) & set(model.keys())
        for field_name in matching:
            if fields[field_name]['indexed'] != model[field_name].index:
                raise RuntimeError(f"Field {field_name} didn't have the expected indexing value.")
            if fields[field_name]['stored'] != model[field_name].store:
                raise RuntimeError(f"Field {field_name} didn't have the expected store value.")

    @collection_reconnect(log)
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
