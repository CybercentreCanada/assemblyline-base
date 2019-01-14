from assemblyline import odm

# TODO: Apply proper index and store values


@odm.model(index=True, store=True)
class PasswordRequirement(odm.Model):
    lower = odm.Boolean()
    number = odm.Boolean()
    special = odm.Boolean()
    upper = odm.Boolean()
    min_length = odm.Integer()


DEFAULT_PASSWORD_REQUIREMENTS = {
    "lower": True,
    "number": False,
    "special": False,
    "upper": True,
    "min_length": 12
}


@odm.model(index=True, store=True)
class SMTP(odm.Model):
    from_adr = odm.Keyword()
    host = odm.Keyword()
    password = odm.Keyword()
    port = odm.Integer()
    tls = odm.Boolean()
    user = odm.Keyword()


DEFAULT_SMTP = {
    "from_adr": "noreply@assemblyline.local",
    "host": "localhost",
    "password": "changeme",
    "port": 587,
    "tls": True,
    "user": "noreply"
}


@odm.model(index=True, store=True)
class Signup(odm.Model):
    enabled = odm.Boolean()
    smtp = odm.Compound(SMTP, default=DEFAULT_SMTP)
    valid_email_patterns = odm.List(odm.Keyword())


DEFAULT_SIGNUP = {
    "enabled": False,
    "smtp": DEFAULT_SMTP,
    "valid_email_patterns": [".*", ".*@assemblyline.local"]
}


@odm.model(index=True, store=True)
class User(odm.Model):
    uname = odm.Keyword()
    name = odm.Keyword()
    password = odm.Keyword()
    groups = odm.List(odm.Keyword())
    is_admin = odm.Boolean()
    classification = odm.Classification(is_user_classification=True)


DEFAULT_USERS = {
    "admin": {
        "uname": "admin",
        "name": "Default admin user",
        "password": "changeme",
        "groups": ["ADMIN", "INTERNAL", "USERS"],
        "is_admin": True,
        "classification": "U"
    },
    "internal": {
        "uname": "internal",
        "name": "Internal re-submission user",
        "password": "Int3rn@lP4s$",
        "groups": ["INTERNAL"],
        "is_admin": False,
        "classification": "U"
    }
}


@odm.model(index=True, store=True)
class Internal(odm.Model):
    enabled = odm.Boolean()
    failure_ttl = odm.Integer()
    max_failures = odm.Integer()
    password_requirements = odm.Compound(PasswordRequirement, default=DEFAULT_PASSWORD_REQUIREMENTS)
    signup = odm.Compound(Signup, default=DEFAULT_SIGNUP)
    users = odm.Mapping(odm.Compound(User), default=DEFAULT_USERS)


DEFAULT_INTERNAL = {
    "enabled": True,
    "failure_ttl": 60,
    "max_failures": 5,
    "password_requirements": DEFAULT_PASSWORD_REQUIREMENTS,
    "signup": DEFAULT_SIGNUP,
    "users": DEFAULT_USERS
}


@odm.model(index=True, store=True)
class Auth(odm.Model):
    allow_2fa = odm.Boolean()
    allow_apikeys = odm.Boolean()
    allow_u2f = odm.Boolean()
    apikey_handler = odm.Keyword()
    dn_handler = odm.Keyword()
    encrypted_login = odm.Boolean()
    internal = odm.Compound(Internal, default=DEFAULT_INTERNAL)
    userpass_handler = odm.Keyword()


DEFAULT_AUTH = {
    "allow_2fa": True,
    "allow_apikeys": True,
    "allow_u2f": True,
    "apikey_handler": 'al_ui.site_specific.validate_apikey',
    "dn_handler": 'al_ui.site_specific.validate_dn',
    "encrypted_login": True,
    "internal": DEFAULT_INTERNAL,
    "userpass_handler": 'al_ui.site_specific.validate_userpass'
}


@odm.model(index=True, store=True)
class RedisServer(odm.Model):
    db = odm.Integer()
    host = odm.Keyword()
    port = odm.Integer()


DEFAULT_REDIS_NP = {
    "db": 0,
    "host": "127.0.0.1",
    "port": 6379
}

DEFAULT_REDIS_P = {
    "db": 0,
    "host": "127.0.0.1",
    "port": 6380
}


@odm.model(index=True, store=True)
class Redis(odm.Model):
    nonpersistent = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP)
    persistent = odm.Compound(RedisServer, default=DEFAULT_REDIS_P)


DEFAULT_REDIS = {
    "nonpersistent": DEFAULT_REDIS_NP,
    "persistent": DEFAULT_REDIS_P
}


@odm.model(index=True, store=True)
class Dispatcher(odm.Model):
    stages = odm.List(odm.Keyword())
    timeout = odm.Float()  # Time between redispatching attempts


DEFAULT_DISPATCHER = {
    "stages": ['setup', 'filter', 'extract', 'core', 'secondary', 'post', 'teardown'],
    "timeout": 5*60
}


@odm.model(index=True, store=True)
class Core(odm.Model):
    redis = odm.Compound(Redis, default=DEFAULT_REDIS)
    dispatcher = odm.Compound(Dispatcher, default=DEFAULT_DISPATCHER)


DEFAULT_CORE = {
    "redis": DEFAULT_REDIS,
    "dispatcher": DEFAULT_DISPATCHER
}


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
    type = odm.Enum({"elasticsearch", "riak", "solr"})
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


@odm.model(index=True, store=True)
class Filestore(odm.Model):
    urls = odm.List(odm.Keyword())


DEFAULT_FILESTORE = {
    "urls": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?use_ssl=False"]
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
    # if yes, what is the syslog server hostname/ip?
    syslog_host = odm.Keyword()


DEFAULT_LOGGING = {
    "log_to_console": True,
    "log_to_file": False,
    "log_directory": "/var/log/assemblyline/",
    "log_to_syslog": False,
    "syslog_host": "localhost"
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class Limits(odm.Model):
    # Maximum number of extracted files
    max_extracted = odm.Integer()
    # Maximum number of supplementary files
    max_supplementary = odm.Integer()


DEFAULT_LIMITS = {
    "max_extracted": 500,
    "max_supplementary": 500
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class Services(odm.Model):
    # Different possible categories
    categories = odm.List(odm.Keyword())
    # Default service timeout time in seconds
    default_timeout = odm.Integer()
    # Limits constraints the the service has to work with
    limits = odm.Compound(Limits, default=DEFAULT_LIMITS)
    # Different stages of execution in order
    stages = odm.List(odm.Keyword())
    # Category for mandatory services (e.g. Sync)
    system_category = odm.Text()


DEFAULT_SERVICES = {
    "categories": ['Antivirus', 'External', 'Extraction', 'Filtering', 'Networking', 'Static Analysis', 'System'],
    "default_timeout": 60,
    "limits": DEFAULT_LIMITS,
    "stages": ['SETUP', 'FILTER', 'EXTRACT', 'CORE', 'SECONDARY', 'POST', 'TEARDOWN'],
    "system_category": 'System'
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class System(odm.Model):
    # Module path to the assemblyline constants
    constants = odm.Keyword()
    # Organisation acronym used for signatures
    organisation = odm.Text()


DEFAULT_SYSTEM = {
    "constants": "assemblyline.common.constants",
    "organisation": "ACME"
}


# This is the model definition for the logging block
@odm.model(index=True, store=True)
class UI(odm.Model):
    # Should API calls be audited and saved to a seperate log file?
    audit = odm.Boolean()
    # Allow to user to download raw files
    allow_raw_downloads = odm.Boolean()
    # Turn on debugging
    debug = odm.Boolean()
    # Which encoding will be used
    download_encoding = odm.Enum(values=["raw", "cart"])
    # Fully qualified domain name to use for the 2-factor authentication validation
    fqdn = odm.Text()
    # Flask secret key to store cookies and stuff
    secret_key = odm.Keyword()


DEFAULT_UI = {
    "audit": True,
    "allow_raw_downloads": True,
    "debug": False,
    "download_encoding": "cart",
    "fqdn": "assemblyline.local",
    "secret_key": "This is the default flask secret key... you should change this!"
}


@odm.model(index=True, store=True)
class Config(odm.Model):
    # Authentication module configuration
    auth = odm.Compound(Auth, default=DEFAULT_AUTH)
    # Core component configuration
    core = odm.Compound(Core, default=DEFAULT_CORE)
    # Datastore configuration
    datastore = odm.Compound(Datastore, default=DEFAULT_DATASTORE)
    # Filestore configuration
    filestore = odm.Compound(Filestore, default=DEFAULT_FILESTORE)
    # Logging configuration
    logging = odm.Compound(Logging, default=DEFAULT_LOGGING)
    # Service configuration
    services = odm.Compound(Services, default=DEFAULT_SERVICES)
    # System configuration
    system = odm.Compound(System, default=DEFAULT_SYSTEM)
    # UI configuration parameters
    ui = odm.Compound(UI, default=DEFAULT_UI)


DEFAULT_CONFIG = {
    "auth": DEFAULT_AUTH,
    "core": DEFAULT_CORE,
    "datastore": DEFAULT_DATASTORE,
    "filestore": DEFAULT_FILESTORE,
    "logging": DEFAULT_LOGGING,
    "services": DEFAULT_SERVICES,
    "system": DEFAULT_SYSTEM,
    "ui": DEFAULT_UI
}
