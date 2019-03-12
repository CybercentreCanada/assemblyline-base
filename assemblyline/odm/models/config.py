from typing import Dict, List
from assemblyline import odm

# TODO: Apply proper index and store values


@odm.model(index=True, store=True)
class PasswordRequirement(odm.Model):
    lower: bool = odm.Boolean()
    number: bool = odm.Boolean()
    special: bool = odm.Boolean()
    upper: bool = odm.Boolean()
    min_length: int = odm.Integer()


DEFAULT_PASSWORD_REQUIREMENTS = {
    "lower": True,
    "number": False,
    "special": False,
    "upper": True,
    "min_length": 12
}


@odm.model(index=True, store=True)
class SMTP(odm.Model):
    from_adr: str = odm.Keyword()
    host: str = odm.Keyword()
    password: str = odm.Keyword()
    port: int = odm.Integer()
    tls: bool = odm.Boolean()
    user: str = odm.Keyword()


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
    enabled: bool = odm.Boolean()
    smtp: SMTP = odm.Compound(SMTP, default=DEFAULT_SMTP)
    valid_email_patterns: List[str] = odm.List(odm.Keyword())


DEFAULT_SIGNUP = {
    "enabled": False,
    "smtp": DEFAULT_SMTP,
    "valid_email_patterns": [".*", ".*@assemblyline.local"]
}


@odm.model(index=True, store=True)
class User(odm.Model):
    uname: str = odm.Keyword()
    name: str = odm.Keyword()
    password: str = odm.Keyword()
    groups: List[str] = odm.List(odm.Keyword())
    is_admin: bool = odm.Boolean()
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
    enabled: bool = odm.Boolean()
    failure_ttl: int = odm.Integer()
    max_failures: int = odm.Integer()
    password_requirements: PasswordRequirement = odm.Compound(PasswordRequirement,
                                                              default=DEFAULT_PASSWORD_REQUIREMENTS)
    signup: Signup = odm.Compound(Signup, default=DEFAULT_SIGNUP)
    users: Dict[str, User] = odm.Mapping(odm.Compound(User), default=DEFAULT_USERS)


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
    allow_2fa: bool = odm.Boolean()
    allow_apikeys: bool = odm.Boolean()
    allow_u2f: bool = odm.Boolean()
    apikey_handler: str = odm.Keyword()
    dn_handler: str = odm.Keyword()
    dn_parser: str = odm.Keyword()
    internal: Internal = odm.Compound(Internal, default=DEFAULT_INTERNAL)
    userpass_handler: str = odm.Keyword()


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
class Alerter(odm.Model):
    alert_ttl: int = odm.Integer()
    constant_alert_fields: List[str] = odm.List(odm.Keyword())
    default_group_field: str = odm.Keyword()
    delay: int = odm.Integer()
    filtering_group_fields: List[str] = odm.List(odm.Keyword())
    non_filtering_group_fields: List[str] = odm.List(odm.Keyword())
    process_alert_message: str = odm.Keyword()


DEFAULT_ALERTER = {
    "alert_ttl": 90,
    "constant_alert_fields": ["alert_id", "file", "ts"],
    "default_group_field": "file.sha256",
    "delay": 300,
    "filtering_group_fields": [
        "file.name",
        "status",
        "priority"
    ],
    "non_filtering_group_fields": [
        "file.md5",
        "file.sha1",
        "file.sha256"
    ],
    "process_alert_message": "al_core.alerter.processing.process_alert_message",

}


@odm.model(index=True, store=True)
class Dispatcher(odm.Model):
    # Time between re-dispatching attempts, as long as some action (submission or any task completion)
    # happens before this timeout ends, the timeout resets.
    timeout: float = odm.Float()
    max_inflight: int = odm.Integer()
    debug_logging: bool = odm.Boolean()


DEFAULT_DISPATCHER = {
    "timeout": 5*60,
    "max_inflight": 1000,
    "debug_logging": False
}


# Configuration options regarding data expiry
@odm.model(index=True, store=True)
class Expiry(odm.Model):
    # By turning on batch delete, delete queries are rounded by day therefor
    # all delete operation happen at the same time at midnight
    batch_delete = odm.Boolean()
    # Delay in hours that will be applied to the expiry query so we can keep
    # data longer then previously set or we can offset deletion during non busy hours
    delay = odm.Integer()
    # Should we also cleanup the file storage?
    delete_storage = odm.Boolean()
    # Time to sleep in between each expiry run (seconds)
    sleep_time = odm.Integer()
    # Number of concurrent workers for linear operations
    workers = odm.Integer()


DEFAULT_EXPIRY = {
    'batch_delete': False,
    'delay': 0,
    'delete_storage': True,
    'sleep_time': 15,
    'workers': 20
}


# Configuration options regarding bulk ingestion and unattended submissions
@odm.model(index=True, store=True)
class Ingester(odm.Model):
    default_user: str = odm.Keyword()
    default_services: List[str] = odm.List(odm.Keyword())
    default_resubmit_services: List[str] = odm.List(odm.Keyword())
    # When a description is automatically generated, it will be the
    # hash prefixed by this string
    description_prefix: str = odm.Keyword()
    # Path to a callback function filtering ingestion tasks that should have their
    # priority forcefully reset to low
    is_low_priority: str = odm.Keyword()
    get_whitelist_verdict: str = odm.Keyword()
    whitelist: str = odm.Keyword()

    # Default values for parameters that may be overridden on a per submission basis
    # How many extracted files may be added to a Submission
    default_max_extracted: int = odm.Integer()
    # How many supplementary files may be added to a submission
    default_max_supplementary: int = odm.Integer()

    # Drop a task altogeather after this many seconds
    expire_after: float = odm.Float()
    stale_after_seconds: float = odm.Float()

    # How long should scores be cached in the ingester
    incomplete_expire_after_seconds: float = odm.Float()
    incomplete_stale_after_seconds: float = odm.Float()

    # How long can a queue get before we start dropping files
    sampling_at: Dict[str, float] = odm.Mapping(odm.Float())


DEFAULT_INGESTER = {
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
class RedisServer(odm.Model):
    db: int = odm.Integer()
    host: str = odm.Keyword()
    port: int = odm.Integer()


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
    nonpersistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP)
    persistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_P)


DEFAULT_REDIS = {
    "nonpersistent": DEFAULT_REDIS_NP,
    "persistent": DEFAULT_REDIS_P
}


@odm.model(index=True, store=True)
class Core(odm.Model):
    alerter: Alerter = odm.Compound(Alerter, default=DEFAULT_ALERTER)
    dispatcher: Dispatcher = odm.Compound(Dispatcher, default=DEFAULT_DISPATCHER)
    expiry: Expiry = odm.Compound(Expiry, default=DEFAULT_EXPIRY)
    ingester: Ingester = odm.Compound(Ingester, default=DEFAULT_INGESTER)
    redis: Redis = odm.Compound(Redis, default=DEFAULT_REDIS)


DEFAULT_CORE = {
    "alerter": DEFAULT_ALERTER,
    "dispatcher": DEFAULT_DISPATCHER,
    "expiry": DEFAULT_EXPIRY,
    "ingester": DEFAULT_INGESTER,
    "redis": DEFAULT_REDIS,
}


@odm.model(index=True, store=True)
class Elasticsearch(odm.Model):
    heap_min_size: int = odm.Integer()
    heap_max_size: int = odm.Integer()
    nodes: List[str] = odm.List(odm.Keyword())


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
    hosts: List[str] = odm.List(odm.Keyword())
    elasticsearch: Elasticsearch = odm.Compound(Elasticsearch, default=DEFAULT_ELASTICSEARCH)
    riak: Riak = odm.Compound(Riak, default=DEFAULT_RIAK)
    solr: Solr = odm.Compound(Solr, default=DEFAULT_SOLR)


DEFAULT_DATASTORE = {
    "type": "elasticsearch",
    "hosts": ["localhost"],
    "elasticsearch": DEFAULT_ELASTICSEARCH,
    "riak": DEFAULT_RIAK,
    "solr": DEFAULT_SOLR
}


@odm.model(index=True, store=True)
class Datasource(odm.Model):
    classpath: str = odm.Keyword()
    config: Dict[str, str] = odm.Mapping(odm.Keyword())


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
    cache: List[str] = odm.List(odm.Keyword())
    storage: List[str] = odm.List(odm.Keyword())


DEFAULT_FILESTORE = {
    "cache": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-cache&use_ssl=False"],
    "storage": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-storage&use_ssl=False"]
}


# This is the model definition for the logging block
@odm.model(index=True, store=True)
class Logging(odm.Model):
    # Should we log to console?
    log_to_console: bool = odm.Boolean()

    # Should we log to files on the server?
    log_to_file: bool = odm.Boolean()
    # if yes, what is the log directory
    log_directory: str = odm.Keyword()

    # Should logs be sent to a syslog server?
    log_to_syslog: bool = odm.Boolean()
    # if yes, what is the syslog server hostname/ip?
    syslog_host: str = odm.Keyword()

    # How often should counters log their values (seconds)
    export_interval: float = odm.Float()


DEFAULT_LOGGING = {
    "log_to_console": True,
    "log_to_file": False,
    "log_directory": "/var/log/assemblyline/",
    "log_to_syslog": False,
    "syslog_host": "localhost",
    "export_interval": 5
}

SERVICE_CATEGORIES = [
    'Antivirus',
    'Dynamic Analysis',
    'External',
    'Extraction',
    'Filtering',
    'Networking',
    'Static Analysis',
    'System'
]
SERVICE_STAGES = [
    'SETUP',
    'FILTER',
    'EXTRACT',
    'CORE',
    'SECONDARY',
    'POST',
    'TEARDOWN'
]

# This is the model definition for the System block
@odm.model(index=True, store=True)
class Services(odm.Model):
    # Different possible categories
    categories: List[str] = odm.List(odm.Keyword())
    # Default service timeout time in seconds
    default_timeout: int = odm.Integer()
    # How many instances of a service should be kept in reserve running even
    # when there doesn't seem to be any work for them to do
    min_service_workers: int = odm.Integer()
    # Different stages of execution in order
    stages: List[str] = odm.List(odm.Keyword())
    # Category for mandatory services (e.g. Sync)
    system_category: str = odm.Text()


DEFAULT_SERVICES = {
    "categories": SERVICE_CATEGORIES,
    "default_timeout": 60,
    "min_service_workers": 0,
    "stages": SERVICE_STAGES,
    "system_category": 'System'
}


# This is the model definition for the Yara Block
@odm.model(index=True, store=True)
class Yara(odm.Model):
    externals: List[str] = odm.List(odm.Keyword())
    importer: str = odm.Keyword()
    parser: str = odm.Keyword()


DEFAULT_YARA = {
    "externals": ['submitter', 'mime', 'tag'],
    "importer": "assemblyline.common.yara.YaraImporter",
    "parser": "assemblyline.common.yara.YaraParser"
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class System(odm.Model):
    # Module path to the assemblyline constants
    constants: str = odm.Keyword()
    # Organisation acronym used for signatures
    organisation: str = odm.Text()
    # Parameter of the yara engine
    yara: Yara = odm.Compound(Yara)


DEFAULT_SYSTEM = {
    "constants": "assemblyline.common.constants",
    "organisation": "ACME",
    "yara": DEFAULT_YARA
}


# This is the model definition for the System block
@odm.model(index=True, store=True)
class Statistics(odm.Model):
    # fields to generated statistics from in the alert page
    alert: List[str] = odm.List(odm.Keyword())
    # fields to generate statistics from in the submission page
    submission: List[str] = odm.List(odm.Keyword())


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
    allow_raw_downloads: bool = odm.Boolean()
    # Allow file submissions via url
    allow_url_submissions: bool = odm.Boolean()
    # Should API calls be audited and saved to a seperate log file?
    audit: bool = odm.Boolean()
    # UI Context
    context: str = odm.Keyword()
    # Turn on debugging
    debug: bool = odm.Boolean()
    # Which encoding will be used
    download_encoding = odm.Enum(values=["raw", "cart"])
    # Assemblyline admins email address
    email: str = odm.Keyword()
    # Enforce the user's quotas
    enforce_quota: bool = odm.Boolean()
    # Fully qualified domain name to use for the 2-factor authentication validation
    fqdn: str = odm.Text()
    # Maximum priority for ingest API
    ingest_max_priority: int = odm.Integer()
    # Turn on read only mode in the UI
    read_only: bool = odm.Boolean()
    # Offset of the read only mode for all paging and searches
    read_only_offset: str = odm.Keyword(default="")
    # Flask secret key to store cookies and stuff
    secret_key: str = odm.Keyword()
    # Duration of the user session before the user has to login again
    session_duration: int = odm.Integer()
    # Statistics configuration
    statistics: Statistics = odm.Compound(Statistics, default=DEFAULT_STATISTICS)
    # Terms of service
    tos: str = odm.Text(default_set=True)
    # Lock out user after accepting the terms of service
    tos_lockout: bool = odm.Boolean()
    # Headers that will be used by the url_download method
    url_submission_headers: Dict[str, str] = odm.Mapping(odm.Keyword(), default_set=True)
    # Proxy that will be used by the url_download method
    url_submission_proxies: Dict[str, str] = odm.Mapping(odm.Keyword(), default_set=True)


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
    "ingest_max_priority": 250,
    "read_only": False,
    "read_only_offset": "",
    "secret_key": "This is the default flask secret key... you should change this!",
    "session_duration": 3600,
    "statistics": DEFAULT_STATISTICS,
    "tos": None,
    "tos_lockout": False,
    "url_submission_headers": {},
    "url_submission_proxies": {}
}


# Options regarding all submissions, regardless of their input method
@odm.model(index=True, store=True)
class Submission(odm.Model):
    # Path to the routine used to
    decode_file: str = odm.Keyword()

    # Default values for parameters that may be overridden on a per submission basis
    # How many extracted files may be added to a Submission
    default_max_extracted: int = odm.Integer()
    # How many supplementary files may be added to a submission
    default_max_supplementary: int = odm.Integer()

    # Number of days submissions will remain in the system by default
    dtl: int = odm.Integer()

    # Maximum files extraction depth
    max_extraction_depth: int = odm.Integer()
    # Maximum size for files submitted in the system
    max_file_size: int = odm.Integer()
    # Maximum length for each metadata keys
    max_metadata_length: int = odm.Integer()

    # Summary tag types
    summary_tag_types: List[str] = odm.List(odm.Keyword())


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
    auth: Auth = odm.Compound(Auth, default=DEFAULT_AUTH)
    # Core component configuration
    core: Core = odm.Compound(Core, default=DEFAULT_CORE)
    # Datastore configuration
    datastore: Datastore = odm.Compound(Datastore, default=DEFAULT_DATASTORE)
    # Datasources configuration
    datasources: Dict[str, Datasource] = odm.Mapping(odm.Compound(Datasource), default=DEFAULT_DATASOURCES)
    # Filestore configuration
    filestore: Filestore = odm.Compound(Filestore, default=DEFAULT_FILESTORE)
    # Logging configuration
    logging: Logging = odm.Compound(Logging, default=DEFAULT_LOGGING)
    # Service configuration
    services: Services = odm.Compound(Services, default=DEFAULT_SERVICES)
    # System configuration
    system: System = odm.Compound(System, default=DEFAULT_SYSTEM)
    # UI configuration parameters
    ui: UI = odm.Compound(UI, default=DEFAULT_UI)
    # Options for how submissions will be processed
    submission: Submission = odm.Compound(Submission, default=DEFAULT_SUBMISSION)


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
