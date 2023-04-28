from __future__ import annotations

import logging
import re
import time
import typing

from os import environ, path
from random import random
from urllib.parse import urlparse

import elasticsearch
import elasticsearch.helpers

from assemblyline.common import forge
from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.exceptions import (DataStoreException, UnsupportedElasticVersion, VersionConflictException)

from packaging import version

TRANSPORT_TIMEOUT = int(environ.get('AL_DATASTORE_TRANSPORT_TIMEOUT', '90'))
DATASTORE_ROOT_CA_PATH = environ.get('DATASTORE_ROOT_CA_PATH', '/etc/assemblyline/ssl/al_root-ca.crt')
log = logging.getLogger('assemblyline.datastore')


class ESStore(object):
    """ Elasticsearch multi-index implementation of the ResultStore interface."""
    MAX_RETRY_BACKOFF = 10
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
    MIN_ELASTIC_VERSION = '7.10'

    def __init__(self, hosts, archive_access=True):
        config = forge.get_config()
        self._hosts = hosts
        self._closed = False
        self._collections = {}
        self._models = {}
        self.archive_indices = config.datastore.archive.indices if config.datastore.archive.enabled else []
        self.validate = True

        tracer = logging.getLogger('elasticsearch')
        tracer.setLevel(logging.CRITICAL)

        self.ca_certs = None if not path.exists(DATASTORE_ROOT_CA_PATH) else DATASTORE_ROOT_CA_PATH

        self.client = elasticsearch.Elasticsearch(hosts=hosts, max_retries=0, request_timeout=TRANSPORT_TIMEOUT,
                                                  ca_certs=self.ca_certs)
        self.es_version = version.parse(self.client.info()['version']['number'])
        self.archive_access = archive_access
        self.url_path = 'elastic'
        self._test_elastic_minimum_version()

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

    def _test_elastic_minimum_version(self):
        if not self.is_supported_version(self.MIN_ELASTIC_VERSION):
            raise UnsupportedElasticVersion(f"Elastic version {self.es_version} is not supported by Assemblyline. "
                                            f"Upgrade to Elastic {self.MIN_ELASTIC_VERSION} at minimum.")

    def is_supported_version(self, min):
        return self.es_version >= version.parse(min)

    def connection_reset(self):
        self.client = elasticsearch.Elasticsearch(hosts=self._hosts,
                                                  max_retries=0,
                                                  request_timeout=TRANSPORT_TIMEOUT,
                                                  ca_certs=self.ca_certs)
        self.es_version = version.parse(self.client.info()['version']['number'])
        self._test_elastic_minimum_version()

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

    def with_retries(self, func, *args, raise_conflicts=False, **kwargs):
        """
        This function performs the passed function with the given args and kwargs and reconnect if it fails

        :return: return the output of the function passed
        """
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

            except elasticsearch.NotFoundError as error:
                index_name = kwargs.get('index', '').upper()
                err_message = str(error)

                # Validate exception type
                if not index_name or "No search context found" not in err_message:
                    raise

                log.warning(f"Index {index_name} was removed while a query was running, retrying...")
                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.connection_reset()
                retries += 1

            except elasticsearch.exceptions.ConflictError as ce:
                if raise_conflicts:
                    # De-sync potential treads trying to write to the index
                    time.sleep(random() * 0.1)
                    raise VersionConflictException(str(ce))
                updated += ce.info.get('updated', 0)
                deleted += ce.info.get('deleted', 0)

                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.connection_reset()
                retries += 1

            except elasticsearch.exceptions.ConnectionTimeout:
                log.warning(f"Elasticsearch connection timeout, server(s): "
                            f"{' | '.join(self.get_hosts(safe=True))}"
                            f", retrying {func.__name__}...")

                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.connection_reset()
                retries += 1

            except (elasticsearch.exceptions.ConnectionError,
                    elasticsearch.exceptions.AuthenticationException) as e:
                log.warning(f"No connection to Elasticsearch server(s): "
                            f"{' | '.join(self.get_hosts(safe=True))}"
                            f", because [{e}] retrying {func.__name__}...")

                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.connection_reset()
                retries += 1

            # Legacy retries, only for elastic 7.x client...
            except elasticsearch.exceptions.TransportError as e:
                err_code, _, _ = e.args
                err_code = int(err_code)
                index_name = kwargs.get('index', '').upper()

                # Validate exception type
                if not index_name or err_code not in [503, 429, 403]:
                    raise

                # Display proper error message
                if err_code == 503:
                    log.warning(f"Looks like index {index_name} is not ready yet, retrying...")
                elif err_code == 429:
                    log.warning("Elasticsearch is too busy to perform the requested "
                                f"task on index {index_name}, retrying...")
                elif err_code == 403:
                    log.warning("Elasticsearch cluster is preventing writing operations "
                                f"on index {index_name}, retrying...")

                # Loop and retry
                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.connection_reset()
                retries += 1

            # Elastic client 8.x retries
            except elasticsearch.AuthorizationException:
                index_name = kwargs.get('index', '').upper()
                if not index_name:
                    raise

                log.warning("Elasticsearch cluster is preventing writing operations "
                            f"on index {index_name}, retrying...")

                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.connection_reset()
                retries += 1

            except elasticsearch.ApiError as err:
                index_name = kwargs.get('index', '').upper()
                err_code = err.meta.status

                # Validate exception type
                if not index_name or err_code not in [503, 429, 403]:
                    raise

                # Display proper error message
                if err_code == 503:
                    log.warning(f"Looks like index {index_name} is not ready yet, retrying...")
                elif err_code == 429:
                    log.warning("Elasticsearch is too busy to perform the requested "
                                f"task on index {index_name}, retrying...")

                # Loop and retry
                time.sleep(min(retries, self.MAX_RETRY_BACKOFF))
                self.connection_reset()
                retries += 1
