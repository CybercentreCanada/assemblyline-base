# This file contains the loaders for the different components of the system
from __future__ import annotations

import elasticapm
import importlib
import os
import time
import yaml

from string import Template
from typing import TYPE_CHECKING

from assemblyline.common.constants import service_queue_name
from assemblyline.common.dict_utils import recursive_update
from assemblyline.common.importing import load_module_by_path

if TYPE_CHECKING:
    from assemblyline.odm.models.config import Config

config_cache = {}


def get_classification(yml_config=None):
    from assemblyline.common.classification import Classification, InvalidDefinition

    if yml_config is None:
        yml_config = "/etc/assemblyline/classification.yml"

    classification_definition = {}
    default_file = os.path.join(os.path.dirname(__file__), "classification.yml")
    if os.path.exists(default_file):
        with open(default_file) as default_fh:
            default_yml_data = yaml.safe_load(default_fh.read())
            if default_yml_data:
                classification_definition.update(default_yml_data)

    # Load modifiers from the yaml config
    if os.path.exists(yml_config):
        with open(yml_config) as yml_fh:
            yml_data = yaml.safe_load(yml_fh.read())
            if yml_data:
                classification_definition = recursive_update(classification_definition, yml_data)

    if not classification_definition:
        raise InvalidDefinition('Could not find any classification definition to load.')

    return Classification(classification_definition)


def env_substitute(buffer):
    """Replace environment variables in the buffer with their value.

    Use the built in template expansion tool that expands environment variable style strings ${}
    We set the idpattern to none so that $abc doesn't get replaced but ${abc} does.

    Case insensitive.
    Variables that are found in the buffer, but are not defined as environment variables are ignored.
    """
    return Template(buffer).safe_substitute(os.environ, idpattern=None, bracedidpattern='(?a:[_a-z][_a-z0-9]*)')


def _get_config(yml_config=None):
    from assemblyline.odm.models.config import Config

    if yml_config is None:
        yml_config = "/etc/assemblyline/config.yml"

    # Initialize a default config
    config = Config().as_primitives()

    # Load modifiers from the yaml config
    if os.path.exists(yml_config):
        with open(yml_config) as yml_fh:
            yml_data = yaml.safe_load(env_substitute(yml_fh.read()))
            if yml_data:
                config = recursive_update(config, yml_data)

    if 'AL_LOG_LEVEL' in os.environ:
        config['logging']['log_level'] = os.environ['AL_LOG_LEVEL']

    return Config(config)


def get_config(yml_config=None) -> Config:
    if yml_config not in config_cache:
        config_cache[yml_config] = _get_config(yml_config=yml_config)
    return config_cache[yml_config]


def get_constants(config=None):
    if config is None:
        config = get_config()
    return importlib.import_module(config.system.constants)


def get_datastore(config=None, archive_access=False):
    from assemblyline.datastore.helper import AssemblylineDatastore
    from assemblyline.datastore.store import ESStore

    if not config:
        config = get_config()

    return AssemblylineDatastore(ESStore(config.datastore.hosts, archive_access=archive_access))


def get_cachestore(component, config=None, datastore=None):
    from assemblyline.cachestore import CacheStore
    return CacheStore(component, config=config, datastore=datastore)


def get_filestore(config=None, connection_attempts=None):
    from assemblyline.filestore import FileStore
    if config is None:
        config = get_config()
    return FileStore(*config.filestore.storage, connection_attempts=connection_attempts)


def get_identify(use_cache=True, config=None, datastore=None, log=None):
    from assemblyline.common.identify import Identify
    return Identify(use_cache=use_cache, config=config, datastore=datastore, log=log)


def get_process_alert_message():
    config = get_config()
    return load_module_by_path(config.core.alerter.process_alert_message)


def get_metrics_sink(redis=None):
    from assemblyline.remote.datatypes.queues.comms import CommsQueue
    return CommsQueue('assemblyline_metrics', host=redis)


def get_service_queue(service: str, redis=None):
    from assemblyline.remote.datatypes.queues.priority import PriorityQueue
    return PriorityQueue(service_queue_name(service), redis)


def get_tag_safelist_data(yml_config=None):

    if yml_config is None:
        yml_config = "/etc/assemblyline/tag_safelist.yml"

    tag_safelist_data = {}
    default_file = os.path.join(os.path.dirname(__file__), "tag_safelist.yml")
    if os.path.exists(default_file):
        with open(default_file) as default_fh:
            default_yml_data = yaml.safe_load(default_fh.read())
            if default_yml_data:
                tag_safelist_data.update(default_yml_data)

    # Load modifiers from the yaml config
    if os.path.exists(yml_config):
        with open(yml_config) as yml_fh:
            yml_data = yaml.safe_load(yml_fh.read())
            if yml_data:
                tag_safelist_data = recursive_update(tag_safelist_data, yml_data)

    return tag_safelist_data


def get_tag_safelister(log=None, yml_config=None, config=None, datastore=None):
    from assemblyline.common.tagging import TagSafelister, InvalidSafelist

    with get_cachestore('system', config=config, datastore=datastore) as cache:
        tag_safelist_yml = cache.get('tag_safelist_yml')
        if tag_safelist_yml:
            tag_safelist_data = yaml.safe_load(tag_safelist_yml)
        else:
            tag_safelist_data = get_tag_safelist_data(yml_config=yml_config)

    if not tag_safelist_data:
        raise InvalidSafelist('Could not find any tag_safelist file to load.')

    return TagSafelister(tag_safelist_data, log=log)


class CachedObject:
    """An object proxy that automatically refreshes its target periodically."""

    def __init__(self, factory, refresh=None, args=None, kwargs=None):
        """
        Args:
            factory: Factory that takes the arguments given in `args` and `kwargs` and produces the proxyed object.
            refresh: Refresh interval in seconds.
        """
        self.__factory = factory
        self.__refresh = float(refresh or 60)
        self.__cached = None
        self.__update_time = 0
        self.__args = args or []
        self.__kwargs = kwargs or {}

    def __reload(self):
        if time.time() - self.__update_time > self.__refresh:
            with elasticapm.capture_span(name=f"CachedObject.reload({self.__factory.__name__})",
                                         span_type="cached_object"):
                self.__cached = self.__factory(*self.__args, **self.__kwargs)
                self.__update_time = time.time()

    def __getattr__(self, key):
        """Forward all attribute requests to the underlying object.

        Refresh the object every `_update_time` seconds.
        """
        self.__reload()
        return getattr(self.__cached, key)

    def __getitem__(self, item):
        self.__reload()
        return self.__cached[item]
