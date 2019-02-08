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
    dn_parser = odm.Keyword()
    internal = odm.Compound(Internal, default=DEFAULT_INTERNAL)
    userpass_handler = odm.Keyword()


DEFAULT_AUTH = {
    "allow_2fa": True,
    "allow_apikeys": True,
    "allow_u2f": True,
    "apikey_handler": 'al_ui.site_specific.validate_apikey',
    "dn_handler": 'al_ui.site_specific.validate_dn',
    "dn_parser": 'al_ui.site_specific.basic_dn_parser',
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
    max_inflight = odm.Integer()


DEFAULT_DISPATCHER = {
    "stages": ['setup', 'filter', 'extract', 'core', 'secondary', 'post', 'teardown'],
    "timeout": 5*60,
    "max_inflight": 1000
}


# Configuration options regarding bulk ingestion and unattended submissions
@odm.model(index=True, store=True)
class Middleman(odm.Model):
    default_user = odm.Keyword()
    default_services = odm.List(odm.Keyword())
    default_resubmit_services = odm.List(odm.Keyword())
    # When a description is automatically generated, it will be the
    # hash prefixed by this string
    description_prefix = odm.Keyword()
    # Path to a callback fuction filtering ingestion tasks that should have their
    # priority forcefully reset to low
    is_low_priority = odm.Keyword()
    get_whitelist_verdict = odm.Keyword()
    whitelist = odm.Keyword()

    # Default values for parameters that may be overridden on a per submission basis
    # How many extracted files may be added to a Submission
    default_max_extracted = odm.Integer()
    # How many supplementary files may be added to a submission
    default_max_supplementary = odm.Integer()

    # Drop a task altogeather after this many seconds
    expire_after = odm.Float()
    stale_after_seconds = odm.Float()

    # TODO ????
    incomplete_expire_after_seconds = odm.Float()
    incomplete_stale_after_seconds = odm.Float()

    # How long can a queue get before we start dropping files
    sampling_at = odm.Mapping(odm.Float())


DEFAULT_MIDDLEMAN = {
    'default_user': 'internal',
    'default_services': [],
    'default_resubmit_services': [],
    'description_prefix': 'Bulk',
    'is_low_priority': 'assemblyline.common.null.always_false',
    'get_whitelist_verdict': 'assemblyline.common.signaturing.drop',
    'whitelist': 'assemblyline.common.null.whitelist',
    'default_max_extracted': 100,
    'default_max_supplementary': 100,
    'expire_after': 15 * 24 * 60 * 60,
    'stale_after_seconds': 1 * 24 * 60 * 60,
    'incomplete_expire_after_seconds': 3600,
    'incomplete_stale_after_seconds': 1800,
    'sampling_at': {
        'low':    10000000,
        'medium':  2000000,
        'high':    1000000,
        'critical': 500000,
    }
}


@odm.model(index=True, store=True)
class Core(odm.Model):
    redis = odm.Compound(Redis, default=DEFAULT_REDIS)
    dispatcher = odm.Compound(Dispatcher, default=DEFAULT_DISPATCHER)
    middleman = odm.Compound(Middleman, default=DEFAULT_MIDDLEMAN)


DEFAULT_CORE = {
    "redis": DEFAULT_REDIS,
    "dispatcher": DEFAULT_DISPATCHER,
    "middleman": DEFAULT_MIDDLEMAN,
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
class Datasource(odm.Model):
    classpath = odm.Keyword()
    config = odm.Mapping(odm.Keyword())


DEFAULT_DATASOURCES = {
    "al": {
        "classpath": 'assemblyline.datasource.al.AL',
        "config": {}
    },
    "alert": {
        "classpath": 'assemblyline.datasource.alert.Alert',
        "config": {}
    }
}


@odm.model(index=True, store=True)
class Filestore(odm.Model):
    cache = odm.List(odm.Keyword())
    storage = odm.List(odm.Keyword())


DEFAULT_FILESTORE = {
    "cache": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-cache&use_ssl=False"],
    "storage": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-storage&use_ssl=False"]
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

    # How often should counters log their values (seconds)
    export_interval = odm.Float()


DEFAULT_LOGGING = {
    "log_to_console": True,
    "log_to_file": False,
    "log_directory": "/var/log/assemblyline/",
    "log_to_syslog": False,
    "syslog_host": "localhost",
    "export_interval": 5
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class Services(odm.Model):
    # Different possible categories
    categories = odm.List(odm.Keyword())
    # Default service timeout time in seconds
    default_timeout = odm.Integer()
    # Different stages of execution in order
    stages = odm.List(odm.Keyword())
    # Category for mandatory services (e.g. Sync)
    system_category = odm.Text()


DEFAULT_SERVICES = {
    "categories": ['Antivirus', 'External', 'Extraction', 'Filtering', 'Networking', 'Static Analysis', 'System'],
    "default_timeout": 60,
    "stages": ['SETUP', 'FILTER', 'EXTRACT', 'CORE', 'SECONDARY', 'POST', 'TEARDOWN'],
    "system_category": 'System'
}


# This is the model definition for the Yara Block
@odm.model(index=True, store=True)
class Yara(odm.Model):
    externals = odm.List(odm.Keyword())
    importer = odm.Keyword()
    parser = odm.Keyword()


DEFAULT_YARA = {
    "externals": ['submitter', 'mime', 'tag'],
    "importer": "assemblyline.common.yara.YaraImporter",
    "parser": "assemblyline.common.yara.YaraParser"
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class System(odm.Model):
    # Module path to the assemblyline constants
    constants = odm.Keyword()
    # Organisation acronym used for signatures
    organisation = odm.Text()
    # Parameter of the yara engine
    yara = odm.Compound(Yara)


DEFAULT_SYSTEM = {
    "constants": "assemblyline.common.constants",
    "organisation": "ACME",
    "yara": DEFAULT_YARA
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class Statistics(odm.Model):
    # fields to generated statistics from in the alert page
    alert = odm.List(odm.Keyword())
    # fields to generate statistics from in the submission page
    submission = odm.List(odm.Keyword())


DEFAULT_STATISTICS = {
    "alert": [
        'al.attrib',
        'al.av',
        'al.domain',
        'al.ip',
        'al.summary',
        'al.yara',
        'file.name',
        'file.md5',
        'owner'
    ],
    "submission": [
        'params.submitter'
    ]
}


# This is the model definition for the logging block
@odm.model(index=True, store=True)
class UI(odm.Model):
    # Allow to user to download raw files
    allow_raw_downloads = odm.Boolean()
    # Allow file submissions via url
    allow_url_submissions = odm.Boolean()
    # Should API calls be audited and saved to a seperate log file?
    audit = odm.Boolean()
    # UI Context
    context = odm.Keyword()
    # Turn on debugging
    debug = odm.Boolean()
    # Which encoding will be used
    download_encoding = odm.Enum(values=["raw", "cart"])
    # Assemblyline admins email address
    email = odm.Keyword()
    # Enforce the user's quotas
    enforce_quota = odm.Boolean()
    # Fully qualified domain name to use for the 2-factor authentication validation
    fqdn = odm.Text()
    # Turn on read only mode in the UI
    read_only = odm.Boolean()
    # Offset of the read only mode for all paging and searches
    read_only_offset = odm.Keyword(default="")
    # Flask secret key to store cookies and stuff
    secret_key = odm.Keyword()
    # Duration of the user session before the user has to login again
    session_duration = odm.Integer()
    # Statistics configuration
    statistics = odm.Compound(Statistics, default=DEFAULT_STATISTICS)
    # Terms of service
    tos = odm.Text(default="")
    # Lock out user after accepting the terms of service
    tos_lockout = odm.Boolean()


DEFAULT_UI = {
    "allow_raw_downloads": True,
    "allow_url_submissions": True,
    "audit": True,
    "context": 'al_ui.site_specific.context',
    "debug": False,
    "download_encoding": "cart",
    "email": 'admin@assemblyline.local',
    "enforce_quota": True,
    "fqdn": "assemblyline.local",
    "read_only": False,
    "read_only_offset": "",
    "secret_key": "This is the default flask secret key... you should change this!",
    "session_duration": 3600,
    "statistics": DEFAULT_STATISTICS,
    "tos": "",
    "tos_lockout": False
}


# Options regarding all submissions, regardless of their input method
@odm.model(index=True, store=True)
class Submission(odm.Model):
    # Path to the routine used to
    decode_file = odm.Keyword()

    # Default values for parameters that may be overridden on a per submission basis
    # How many extracted files may be added to a Submission
    default_max_extracted = odm.Integer()
    # How many supplementary files may be added to a submission
    default_max_supplementary = odm.Integer()

    # Number of days submissions will remain in the system by default
    dtl = odm.Integer()

    # Maximum files extraction depth
    max_extraction_depth = odm.Integer()
    # Maximum size for files submitted in the system
    max_file_size = odm.Integer()
    # Maximum length for each metadata keys
    max_metadata_length = odm.Integer()

    # Summary tag types
    summary_tag_types = odm.List(odm.Keyword())


DEFAULT_SUBMISSION = {
    'decode_file': 'assemblyline.common.codec.decode_file',
    'default_max_extracted': 500,
    'default_max_supplementary': 500,
    'dtl': 15,
    'max_extraction_depth': 6,
    'max_file_size': 104857600,
    'max_metadata_length': 4096,
    'summary_tag_types': [
        'NET_IP',
        'NET_DOMAIN_NAME',
        'NET_FULL_URI',
        'AV_VIRUS_NAME',
        'IMPLANT_NAME',
        'IMPLANT_FAMILY',
        'TECHNIQUE_OBFUSCATION',
        'THREAT_ACTOR',
        'FILE_CONFIG',
        'FILE_OBFUSCATION',
        'EXPLOIT_NAME',
        'FILE_SUMMARY'
    ]
}


@odm.model(index=True, store=True)
class Config(odm.Model):
    # Authentication module configuration
    auth = odm.Compound(Auth, default=DEFAULT_AUTH)
    # Core component configuration
    core = odm.Compound(Core, default=DEFAULT_CORE)
    # Datastore configuration
    datastore = odm.Compound(Datastore, default=DEFAULT_DATASTORE)
    # Datasources configuration
    datasources = odm.Mapping(odm.Compound(Datasource), default=DEFAULT_DATASOURCES)
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
    # Options for how submissions will be processed
    submission = odm.Compound(Submission, default=DEFAULT_SUBMISSION)


DEFAULT_CONFIG = {
    "auth": DEFAULT_AUTH,
    "core": DEFAULT_CORE,
    "datastore": DEFAULT_DATASTORE,
    "datasources": DEFAULT_DATASOURCES,
    "filestore": DEFAULT_FILESTORE,
    "logging": DEFAULT_LOGGING,
    "services": DEFAULT_SERVICES,
    "system": DEFAULT_SYSTEM,
    "ui": DEFAULT_UI,
    "submission": DEFAULT_SUBMISSION,
}
