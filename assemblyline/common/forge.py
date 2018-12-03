# This file contains the loaders for the different components of the system


def get_config(yml_config="/etc/assemblyline/config.yml"):
    from assemblyline.odm.models.config import Config

    # Initialize a default config
    config = Config().as_primitives()
    # TODO: Load yml config file to bootstrap the current system config
    # config.update(yml_config)
    # TODO: Load a datastore object and load the config changes from the datastore
    # config.update(datastore_changes)
    return Config(config)


def get_datastore(config=None):
    if not config:
        config = get_config()

    if config.datastore.type == "elasticsearch":
        from assemblyline.datastore.stores.es_store import ESStore
        return ESStore(config.datastore.hosts)
    elif config.datastore.type == "riak":
        from assemblyline.datastore.stores.riak_store import RiakStore
        return RiakStore(config.datastore.hosts,
                         solr_port=config.datastore.riak.solr_port,
                         riak_http_port=config.datastore.riak.riak_http_port,
                         riak_pb_port=config.datastore.riak.riak_pb_port)
    elif config.datastore.type == "solr":
        from assemblyline.datastore.stores.solr_store import SolrStore
        return SolrStore(config.datastore.hosts, port=config.datastore.solr.port)
    else:
        from assemblyline.datastore.exceptions import DataStoreException
        raise DataStoreException(f"Invalid datastore type: {config.datastore.type}")
