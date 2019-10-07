from typing import Dict, List

from assemblyline import odm
# TODO: Apply proper index and store values
from assemblyline.common.constants import FILE_QUEUE, SUBMISSION_QUEUE
from assemblyline.odm.models.service import EnvironmentVariable, DockerConfig
from assemblyline.odm.models.user import USER_TYPES


@odm.model()
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


@odm.model()
class Notify(odm.Model):
    base_url: str = odm.Optional(odm.Keyword())
    api_key: str = odm.Optional(odm.Keyword())
    registration_template: str = odm.Optional(odm.Keyword())
    password_reset_template: int = odm.Optional(odm.Keyword())


DEFAULT_NOTIFY = {
    "base_url": None,
    "api_key": None,
    "registration_template": None,
    "password_reset_template": None,
}

@odm.model()
class SMTP(odm.Model):
    from_adr: str = odm.Optional(odm.Keyword())
    host: str = odm.Optional(odm.Keyword())
    password: str = odm.Optional(odm.Keyword())
    port: int = odm.Integer()
    tls: bool = odm.Boolean()
    user: str = odm.Optional(odm.Keyword())


DEFAULT_SMTP = {
    "from_adr": None,
    "host": None,
    "password": None,
    "port": 587,
    "tls": True,
    "user": None
}


@odm.model()
class Signup(odm.Model):
    enabled: bool = odm.Boolean()
    smtp: SMTP = odm.Compound(SMTP, default=DEFAULT_SMTP)
    notify: Notify = odm.Compound(Notify, default=DEFAULT_NOTIFY)
    valid_email_patterns: List[str] = odm.List(odm.Keyword())


DEFAULT_SIGNUP = {
    "enabled": False,
    "notify": DEFAULT_NOTIFY,
    "smtp": DEFAULT_SMTP,
    "valid_email_patterns": [".*", ".*@localhost"]
}


@odm.model()
class User(odm.Model):
    uname: str = odm.Keyword()
    name: str = odm.Keyword()
    password: str = odm.Keyword()
    groups: List[str] = odm.List(odm.Keyword())
    type: bool = odm.List(odm.Enum(values=USER_TYPES))
    classification = odm.Classification(is_user_classification=True)


DEFAULT_USERS = {
    "admin": {
        "uname": "admin",
        "name": "Default admin user",
        "password": "changeme",
        "groups": ["ADMIN", "INTERNAL", "USERS"],
        "type": ['admin', 'user'],
        "classification": "UNRESTRICTED"
    },
    "internal": {
        "uname": "internal",
        "name": "Internal re-submission user",
        "password": "Int3rn@lP4s$",
        "groups": ["INTERNAL"],
        "type": ['user'],
        "classification": "UNRESTRICTED"
    }
}


@odm.model()
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


@odm.model()
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
    "apikey_handler": 'assemblyline_ui.site_specific.validate_apikey',
    "dn_handler": 'assemblyline_ui.site_specific.validate_dn',
    "dn_parser": 'assemblyline_ui.site_specific.basic_dn_parser',
    "internal": DEFAULT_INTERNAL,
    "userpass_handler": 'assemblyline_ui.site_specific.validate_userpass'
}


@odm.model()
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
    "process_alert_message": "assemblyline_core.alerter.processing.process_alert_message",

}


@odm.model()
class Dispatcher(odm.Model):
    # Time between re-dispatching attempts, as long as some action (submission or any task completion)
    # happens before this timeout ends, the timeout resets.
    timeout: float = odm.Integer()
    max_inflight: int = odm.Integer()


DEFAULT_DISPATCHER = {
    "timeout": 15*60,
    "max_inflight": 1000
}


# Configuration options regarding data expiry
@odm.model()
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
@odm.model()
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
    expire_after: int = odm.Integer()
    stale_after_seconds: int = odm.Integer()

    # How long should scores be cached in the ingester
    incomplete_expire_after_seconds: int = odm.Integer()
    incomplete_stale_after_seconds: int = odm.Integer()

    # How long can a queue get before we start dropping files
    sampling_at: Dict[str, int] = odm.Mapping(odm.Integer())


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


@odm.model()
class RedisServer(odm.Model):
    host: str = odm.Keyword()
    port: int = odm.Integer()


DEFAULT_REDIS_NP = {
    "host": "127.0.0.1",
    "port": 6379
}

DEFAULT_REDIS_P = {
    "host": "127.0.0.1",
    "port": 6380
}


@odm.model()
class ESMetrics(odm.Model):
    hosts: str = odm.Optional(odm.List(odm.Keyword()))


DEFAULT_ES_METRICS = {
    'hosts': None
}


@odm.model()
class KBMetrics(odm.Model):
    host: str = odm.Optional(odm.Keyword())
    password: str = odm.Keyword()
    port: int = odm.Integer()


DEFAULT_KB_METRICS = {
    'host': None,
    'password': 'kibana',
    'port': 5601
}


@odm.model()
class APMServer(odm.Model):
    server_url: str = odm.Optional(odm.Keyword())
    token: str = odm.Optional(odm.Keyword())


DEFAULT_APM_SERVER = {
    'server_url': None,
    'token': None
}


@odm.model()
class Metrics(odm.Model):
    apm_server: APMServer = odm.Compound(APMServer, default=DEFAULT_APM_SERVER)
    elasticsearch: ESMetrics = odm.Compound(ESMetrics, default=DEFAULT_ES_METRICS)
    export_interval: int = odm.Integer()
    kibana: KBMetrics = odm.Compound(KBMetrics, default=DEFAULT_KB_METRICS)
    redis: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP)


DEFAULT_METRICS = {
    'apm_server': DEFAULT_APM_SERVER,
    'elasticsearch': DEFAULT_ES_METRICS,
    'export_interval': 5,
    'kibana': DEFAULT_KB_METRICS,
    'redis': DEFAULT_REDIS_NP,
}


@odm.model()
class Redis(odm.Model):
    nonpersistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP)
    persistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_P)


DEFAULT_REDIS = {
    "nonpersistent": DEFAULT_REDIS_NP,
    "persistent": DEFAULT_REDIS_P
}


@odm.model()
class ScalerProfile(odm.Model):
    """Minimal description for an assemblyline core component controlled by the scaler."""
    growth: int = odm.Optional(odm.Integer())
    shrink: int = odm.Optional(odm.Integer())
    backlog: int = odm.Optional(odm.Integer())
    min_instances: int = odm.Optional(odm.Integer())
    max_instances: int = odm.Optional(odm.Integer())
    queue: str = odm.Keyword()
    container_config: DockerConfig = odm.Compound(DockerConfig)


@odm.model()
class ScalerServiceDefaults(odm.Model):
    """A set of default values to be used running a service when no other value is set."""
    growth: int = odm.Integer()
    shrink: int = odm.Integer()
    backlog: int = odm.Integer()
    min_instances: int = odm.Integer()
    environment: List[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[])

    def apply(self, profile: ScalerProfile) -> dict:
        data = profile.as_primitives(strip_null=True)
        data.setdefault('growth', self.growth)
        data.setdefault('shrink', self.shrink)
        data.setdefault('backlog', self.backlog)
        data.setdefault('min_instances', self.min_instances)
        data['container_config'] = DockerConfig(data['container_config'])
        set_keys = set(var.name for var in profile.container_config.environment)
        for var in self.environment:
            if var.name not in set_keys:
                data['container_config'].environment.append(var)
        return data


@odm.model()
class Scaler(odm.Model):
    service_defaults: ScalerServiceDefaults = odm.Compound(ScalerServiceDefaults)
    core_defaults: ScalerServiceDefaults = odm.Compound(ScalerServiceDefaults)
    core_configs = odm.Mapping(odm.Compound(ScalerProfile))

    core_namespace: str = odm.Keyword()
    service_namespace: str = odm.Keyword()


DEFAULT_SCALER = {
    'service_defaults': {
        'growth': 60,
        'shrink': 60,
        'backlog': 100,
        'min_instances': 0,
        'environment': [{'name': 'SERVICE_API_HOST', 'value': 'http://al_service_server:5003'}],
    },
    'core_defaults': {
        'growth': 60,
        'shrink': 60,
        'backlog': 100,
        'min_instances': 1,
        'environment': [],
    },
    'core_configs': {
        'dispatcher_files': {
            'container_config': {
                'image': 'cccs/assemblyline_dev:4.0.9',
                'command': ['python3', '/opt/alv4/alv4_core/assemblyline_core/dispatching/run_files.py'],
            },
            'queue': FILE_QUEUE
        },
        'dispatcher_submissions': {
            'container_config': {
                'image': 'cccs/assemblyline_dev:4.0.9',
                'command': ['python3', '/opt/alv4/alv4_core/assemblyline_core/dispatching/run_submissions.py'],
            },
            'queue': SUBMISSION_QUEUE
        }
    },
    'core_namespace': 'al',
    'service_namespace': 'alsvc',
}


@odm.model()
class Core(odm.Model):
    alerter: Alerter = odm.Compound(Alerter, default=DEFAULT_ALERTER)
    dispatcher: Dispatcher = odm.Compound(Dispatcher, default=DEFAULT_DISPATCHER)
    expiry: Expiry = odm.Compound(Expiry, default=DEFAULT_EXPIRY)
    ingester: Ingester = odm.Compound(Ingester, default=DEFAULT_INGESTER)
    metrics: Metrics = odm.Compound(Metrics, default=DEFAULT_METRICS)
    redis: Redis = odm.Compound(Redis, default=DEFAULT_REDIS)
    scaler: Scaler = odm.Compound(Scaler, default=DEFAULT_SCALER)


DEFAULT_CORE = {
    "alerter": DEFAULT_ALERTER,
    "dispatcher": DEFAULT_DISPATCHER,
    "expiry": DEFAULT_EXPIRY,
    "ingester": DEFAULT_INGESTER,
    "metrics": DEFAULT_METRICS,
    "redis": DEFAULT_REDIS,
    "scaler": DEFAULT_SCALER,
}


@odm.model()
class Elasticsearch(odm.Model):
    heap_min_size: int = odm.Integer()
    heap_max_size: int = odm.Integer()
    nodes: List[str] = odm.List(odm.Keyword())


DEFAULT_ELASTICSEARCH = {
    "heap_min_size": 1,
    "heap_max_size": 4,
    "nodes": ['localhost']
}


@odm.model()
class Solr(odm.Model):
    # TODO: Model definition for Solr needs to be done
    pass


DEFAULT_SOLR = {}


@odm.model()
class Datastore(odm.Model):
    type = odm.Enum({"elasticsearch", "solr"})
    hosts: List[str] = odm.List(odm.Keyword())
    elasticsearch: Elasticsearch = odm.Compound(Elasticsearch, default=DEFAULT_ELASTICSEARCH)
    solr: Solr = odm.Compound(Solr, default=DEFAULT_SOLR)


DEFAULT_DATASTORE = {
    "type": "elasticsearch",
    "hosts": ["localhost"],
    "elasticsearch": DEFAULT_ELASTICSEARCH,
    "solr": DEFAULT_SOLR
}


@odm.model()
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


@odm.model()
class Filestore(odm.Model):
    cache: List[str] = odm.List(odm.Keyword())
    storage: List[str] = odm.List(odm.Keyword())


DEFAULT_FILESTORE = {
    "cache": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-cache&use_ssl=False"],
    "storage": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-storage&use_ssl=False"]
}


# This is the model definition for the logging block
@odm.model()
class Logging(odm.Model):
    # What level of logging should we have
    log_level: str = odm.Enum(values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "DISABLED"])

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
    export_interval: int = odm.Integer()


DEFAULT_LOGGING = {
    "log_level": "INFO",
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
]

SERVICE_STAGES = [
    'FILTER',
    'EXTRACT',
    'CORE',
    'SECONDARY',
    'POST'
]

# This is the model definition for the System block
@odm.model()
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


DEFAULT_SERVICES = {
    "categories": SERVICE_CATEGORIES,
    "default_timeout": 60,
    "min_service_workers": 0,
    "stages": SERVICE_STAGES,
}


# This is the model definition for the Yara Block
@odm.model()
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
@odm.model()
class System(odm.Model):
    # Module path to the assemblyline constants
    constants: str = odm.Keyword()
    # Organisation acronym used for signatures
    organisation: str = odm.Text()
    # Type of system (production, staging, development)
    type: str = odm.Enum(values=['production', 'staging', 'development'])
    # Parameter of the yara engine
    yara: Yara = odm.Compound(Yara)


DEFAULT_SYSTEM = {
    "constants": "assemblyline.common.constants",
    "organisation": "ACME",
    "type": 'production',
    "yara": DEFAULT_YARA
}


# This is the model definition for the System block
@odm.model()
class Statistics(odm.Model):
    # fields to generated statistics from in the alert page
    alert: List[str] = odm.List(odm.Keyword())
    # fields to generate statistics from in the submission page
    submission: List[str] = odm.List(odm.Keyword())


DEFAULT_STATISTICS = {
    "alert": [
        'al.attrib',
        'al.av',
        'al.behavior',
        'al.domain',
        'al.ip',
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
@odm.model()
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
    tos: str = odm.Optional(odm.Text())
    # Lock out user after accepting the terms of service
    tos_lockout: bool = odm.Boolean()
    # Headers that will be used by the url_download method
    url_submission_headers: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()))
    # Proxy that will be used by the url_download method
    url_submission_proxies: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()))


DEFAULT_UI = {
    "allow_raw_downloads": True,
    "allow_url_submissions": True,
    "audit": True,
    "context": 'assemblyline_ui.site_specific.context',
    "debug": False,
    "download_encoding": "cart",
    "email": 'admin@localhost',
    "enforce_quota": True,
    "fqdn": "localhost",
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
@odm.model()
class TagTypes(odm.Model):
    attribution: List[str] = odm.List(odm.Keyword())
    behavior: List[str] = odm.List(odm.Keyword())
    ioc: List[str] = odm.List(odm.Keyword())


DEFAULT_TAG_TYPES = {
    'attribution': [
        'attribution.actor',
        'attribution.campaign',
        'attribution.exploit',
        'attribution.implant',
        'attribution.family',
        'attribution.network',
        'av.virus_name',
        'file.config',
        'techinique.obfuscation',
    ],
    'behavior': [
        'file.behavior'
    ],
    'ioc': [
        'network.email.address',
        'network.ip',
        'network.domain',
        'network.uri',

    ]
}

# Options regarding all submissions, regardless of their input method
@odm.model()
class Submission(odm.Model):
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
    tag_types = odm.Compound(TagTypes, default=DEFAULT_TAG_TYPES)


DEFAULT_SUBMISSION = {
    'default_max_extracted': 500,
    'default_max_supplementary': 500,
    'dtl': 15,
    'max_extraction_depth': 6,
    'max_file_size': 104857600,
    'max_metadata_length': 4096,
    'tag_types': DEFAULT_TAG_TYPES
}


@odm.model()
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
