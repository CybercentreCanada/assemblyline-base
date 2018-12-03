from assemblyline import odm


@odm.model(index=True, store=True)
class Elasticsearch(odm.Model):
    heap_min_size = odm.Integer()
    heap_max_size = odm.Integer()
    nodes = odm.List(odm.Keyword())


DEFAULT_ELASTICSEARCH = {
    "heap_min_size": 1,
    "heap_max_size": 4,
    "nodes": ['localhost']
}


@odm.model(index=True, store=True)
class Riak(odm.Model):
    # TODO: Model definition for Riak needs to be done
    pass


DEFAULT_RIAK = {}


@odm.model(index=True, store=True)
class Solr(odm.Model):
    # TODO: Model definition for Solr needs to be done
    pass


DEFAULT_SOLR = {}


@odm.model(index=True, store=True)
class Datastore(odm.Model):
    type = odm.Keyword()
    hosts = odm.List(odm.Keyword())
    elasticsearch = odm.Compound(Elasticsearch, default=DEFAULT_ELASTICSEARCH)
    riak = odm.Compound(Riak, default=DEFAULT_RIAK)
    solr = odm.Compound(Solr, default=DEFAULT_SOLR)

DEFAULT_DATASTORE = {
    "type": "elasticsearch",
    "hosts": ["localhost"],
    "elasticsearch": DEFAULT_ELASTICSEARCH,
    "riak": DEFAULT_RIAK,
    "solr": DEFAULT_SOLR
}


# This is the model definition for the logging block
@odm.model(index=True, store=True)
class Logging(odm.Model):
    # Should we log to console?
    log_to_console = odm.Boolean()

    # Should we log to files on the server?
    log_to_file = odm.Boolean()
    # if yes, what is the log directory
    log_directory = odm.Keyword()

    # Should logs be sent to a syslog server?
    log_to_syslog = odm.Boolean()
    # if yes, what is the syslog server IP?
    syslog_ip = odm.Keyword()


DEFAULT_LOGGING = {
    "log_to_console": True,
    "log_to_file": False,
    "log_directory": "/var/log/assemblyline/",
    "log_to_syslog": False,
    "syslog_ip": "127.0.0.1"
}


@odm.model(index=True, store=True)
class Config(odm.Model):
    datastore = odm.Compound(Datastore, default=DEFAULT_DATASTORE)
    logging = odm.Compound(Logging, default=DEFAULT_LOGGING)


DEFAULT_CONFIG = {
    "datastore": DEFAULT_DATASTORE,
    "logging": DEFAULT_LOGGING
}


def get_config(yml_config="/etc/assemblyline/config.yml"):
    # Initialize a default config
    config = Config().as_primitives()
    # TODO: Load yml config file to bootstrap the current system config
    # config.update(yml_config)
    # TODO: Load a datastore object and load the config changes from the datastore
    # config.update(datastore_changes)
    return Config(config)
