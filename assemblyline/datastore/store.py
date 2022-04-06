from __future__ import annotations

import logging
import re
from os import environ
import typing
from urllib.parse import urlparse

import elasticsearch
import elasticsearch.helpers

from assemblyline.common import forge
from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.exceptions import DataStoreException

TRANSPORT_TIMEOUT = int(environ.get('AL_DATASTORE_TRANSPORT_TIMEOUT', '10'))


class ESStore(object):
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
    ID = 'id'

    def __init__(self, hosts, collection_class=ESCollection, archive_access=True):
        config = forge.get_config()
        if config.datastore.ilm.enabled:
            ilm_config = config.datastore.ilm.indexes.as_primitives()
        else:
            ilm_config = {}

        self._hosts = hosts
        self._closed = False
        self._collections = {}
        self._models = {}
        self.ilm_config = ilm_config
        self.validate = True

        tracer = logging.getLogger('elasticsearch')
        tracer.setLevel(logging.CRITICAL)

        self.client = elasticsearch.Elasticsearch(hosts=hosts,
                                                  connection_class=elasticsearch.RequestsHttpConnection,
                                                  max_retries=0,
                                                  timeout=TRANSPORT_TIMEOUT)
        self.archive_access = archive_access
        self.url_path = 'elastic'

    def __enter__(self):
        return self

    def __exit__(self, ex_type, exc_val, exc_tb):
        self.close()

    def __str__(self):
        return '{0} - {1}'.format(self.__class__.__name__, self._hosts)

    def __getattr__(self, name) -> ESCollection:
        if not self.validate:
            return ESCollection(self, name, model_class=self._models[name], validate=self.validate)

        if name not in self._collections:
            self._collections[name] = ESCollection(
                self, name, model_class=self._models[name], validate=self.validate)

        return self._collections[name]

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

    def connection_reset(self):
        self.client = elasticsearch.Elasticsearch(hosts=self._hosts,
                                                  connection_class=elasticsearch.RequestsHttpConnection,
                                                  max_retries=0,
                                                  timeout=TRANSPORT_TIMEOUT)

    def close(self):
        self._closed = True
        # Flatten the client object so that attempts to access without reconnecting errors hard
        # But 'cast' it so that mypy and other linters don't think that its normal for client to be None
        self.client = typing.cast(elasticsearch.Elasticsearch, None)

    def get_hosts(self, safe=False):
        if not safe:
            return self._hosts
        else:
            out = []
            for h in self._hosts:
                parsed = urlparse(h)
                out.append(parsed.hostname or parsed.path)
            return out

    def get_models(self):
        return self._models

    def is_closed(self):
        return self._closed

    def ping(self):
        return self.client.ping()

    def register(self, name: str, model_class=None):
        name_match = re.match(r'[a-z0-9_]*', name)
        if not name_match or name_match.string != name:
            raise DataStoreException('Invalid characters in model name. '
                                     'You can only use lower case letters, numbers and underscores.')

        self._models[name] = model_class

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
