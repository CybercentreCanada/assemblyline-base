# This file contains the loaders for the different components of the system
import collections
import importlib
import time
import os
import yaml

from easydict import EasyDict

from assemblyline.cachestore import CacheStore
from assemblyline.common.importing import load_module_by_path
from assemblyline.filestore import FileStore


def recursive_update(d, u):
    for k, v in u.items():
        if isinstance(v, collections.Mapping):
            d[k] = recursive_update(d.get(k, {}), v)
        else:
            d[k] = v

    return d


def get_classification(yml_config=None):
    from assemblyline.common.classification import Classification, InvalidDefinition

    if yml_config is None:
        yml_config = "/etc/assemblyline/classification.yml"

    classification_definition = {}
    default_file = os.path.join(os.path.dirname(__file__), "classification.yml")
    if os.path.exists(default_file):
        with open(default_file) as default_fh:
            default_yml_data = yaml.load(default_fh.read())
            if default_yml_data:
                classification_definition.update(default_yml_data)

    # Load modifiers from the yaml config
    if os.path.exists(yml_config):
        with open(yml_config) as yml_fh:
            yml_data = yaml.load(yml_fh.read())
            if yml_data:
                classification_definition = recursive_update(classification_definition, yml_data)

    if not classification_definition:
        raise InvalidDefinition('Could not find any classification definition to load.')

    return Classification(classification_definition)


def _get_config(static=False, yml_config=None):
    from assemblyline.odm.models.config import Config

    if yml_config is None:
        yml_config = "/etc/assemblyline/config.yml"

    # Initialize a default config
    config = Config().as_primitives()

    # Load modifiers from the yaml config
    if os.path.exists(yml_config):
        with open(yml_config) as yml_fh:
            yml_data = yaml.load(yml_fh.read())
            if yml_data:
                config = recursive_update(config, yml_data)

    if not static:
        # TODO: Load a datastore object and load the config changes from the datastore
        # config.update(datastore_changes)
        pass
    return Config(config)


def get_config(static=False, yml_config=None):
    return CachedObject(_get_config, kwargs={'static': static, 'yml_config': yml_config})


def get_constants(config=None):
    if config is None:
        config = get_config()
    return importlib.import_module(config.system.constants)


def get_datastore(config=None):
    from assemblyline.datastore.helper import AssemblylineDatastore
    if not config:
        config = get_config(static=True)

    if config.datastore.type == "elasticsearch":
        from assemblyline.datastore.stores.es_store import ESStore
        return AssemblylineDatastore(ESStore(config.datastore.hosts))
    elif config.datastore.type == "riak":
        from assemblyline.datastore.stores.riak_store import RiakStore
        return AssemblylineDatastore(RiakStore(config.datastore.hosts,
                                               solr_port=config.datastore.riak.solr_port,
                                               riak_http_port=config.datastore.riak.riak_http_port,
                                               riak_pb_port=config.datastore.riak.riak_pb_port))
    elif config.datastore.type == "solr":
        from assemblyline.datastore.stores.solr_store import SolrStore
        return AssemblylineDatastore(SolrStore(config.datastore.hosts, port=config.datastore.solr.port))
    else:
        from assemblyline.datastore.exceptions import DataStoreException
        raise DataStoreException(f"Invalid datastore type: {config.datastore.type}")


def get_dn_parser(config=None):
    if config is None:
        config = get_config()
    try:
        return load_module_by_path(config.auth.dn_parser)
    except ImportError:
        return None


def get_cachestore(component, config=None, datastore=None):
    return CacheStore(component, config=config, datastore=datastore)


def get_filestore(config=None):
    if config is None:
        config = get_config()
    return FileStore(*config.filestore.storage)


def get_process_alert_message():
    config = get_config()
    return load_module_by_path(config.core.alerter.process_alert_message)


def get_site_specific_apikey_handler(config=None):
    if config is None:
        config = get_config()
    return load_module_by_path(config.auth.apikey_handler)


def get_site_specific_dn_handler(config=None):
    if config is None:
        config = get_config()
    return load_module_by_path(config.auth.dn_handler)


def get_site_specific_userpass_handler(config=None):
    if config is None:
        config = get_config()
    return load_module_by_path(config.auth.userpass_handler)


def get_ui_context(config=None):
    if config is None:
        config = get_config()
    return EasyDict(load_module_by_path(config.ui.context))


def get_metrics_sink(redis=None):
    from assemblyline.remote.datatypes.queues.comms import CommsQueue
    return CommsQueue('assemblyline_metrics', host=redis)


class CachedObject:
    """An object proxy that automatically refreshes its target periodically."""

    def __init__(self, factory, refresh=5, args=None, kwargs=None):
        """
        Args:
            factory: Factory that takes no arguments and returns only the object to be wrapped.
            refresh: Refresh rate in seconds.
        """
        self._factory = factory
        self._refresh = refresh
        self._cached = None
        self._update_time = 0
        self._args = args or []
        self._kwargs = kwargs or {}

    def __getattr__(self, key):
        """Forward all attribute requests to the underlying object.

        Refresh the object every `_update_time` seconds.
        """
        if time.time() - self._update_time > self._refresh:
            self._cached = self._factory(*self._args, **self._kwargs)
            self._update_time = time.time()
        return getattr(self._cached, key)

    def __getitem__(self, item):
        if time.time() - self._update_time > self._refresh:
            self._cached = self._factory()
            self._update_time = time.time()
        return self._cached[item]
