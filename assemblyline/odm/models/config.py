from typing import Dict, List

from assemblyline import odm
from assemblyline.odm.models.service import EnvironmentVariable

OAUTH_AUTO_PROPERTY_TYPE = ['access', 'classification', 'role']


@odm.model(index=False, store=False)
class PasswordRequirement(odm.Model):
    lower: bool = odm.Boolean()
    number: bool = odm.Boolean()
    special: bool = odm.Boolean()
    upper: bool = odm.Boolean()
    min_length: int = odm.Integer()


DEFAULT_PASSWORD_REQUIREMENTS = {
    "lower": False,
    "number": False,
    "special": False,
    "upper": False,
    "min_length": 12
}


@odm.model(index=False, store=False)
class Notify(odm.Model):
    base_url: str = odm.Optional(odm.Keyword())
    api_key: str = odm.Optional(odm.Keyword())
    registration_template: str = odm.Optional(odm.Keyword())
    password_reset_template: str = odm.Optional(odm.Keyword())
    authorization_template: str = odm.Optional(odm.Keyword())
    activated_template: str = odm.Optional(odm.Keyword())


DEFAULT_NOTIFY = {
    "base_url": None,
    "api_key": None,
    "registration_template": None,
    "password_reset_template": None,
    "authorization_template": None,
    "activated_template": None,
}


@odm.model(index=False, store=False)
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


@odm.model(index=False, store=False)
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


@odm.model(index=False, store=False)
class LDAP(odm.Model):
    enabled: bool = odm.Boolean()
    admin_dn: str = odm.Optional(odm.Keyword())
    bind_user: str = odm.Optional(odm.Keyword())
    bind_pass: str = odm.Optional(odm.Keyword())
    auto_create: bool = odm.Boolean()
    auto_sync: bool = odm.Boolean()
    base: str = odm.Keyword()
    classification_mappings: Dict[str, str] = odm.Any()
    email_field: str = odm.Keyword()
    group_lookup_query: str = odm.Keyword()
    image_field: str = odm.Keyword()
    image_format: str = odm.Keyword()
    name_field: str = odm.Keyword()
    signature_importer_dn: str = odm.Optional(odm.Keyword())
    signature_manager_dn: str = odm.Optional(odm.Keyword())
    uid_field: str = odm.Keyword()
    uri: str = odm.Keyword()


DEFAULT_LDAP = {
    "enabled": False,
    "admin_dn": None,
    "bind_user": None,
    "bind_pass": None,
    "auto_create": True,
    "auto_sync": True,
    "base": "ou=people,dc=assemblyline,dc=local",
    "classification_mappings": {},
    "email_field": "mail",
    "group_lookup_query": "(&(objectClass=Group)(member=%s))",
    "image_field": "jpegPhoto",
    "image_format": "jpeg",
    "name_field": "cn",
    "signature_importer_dn": None,
    "signature_manager_dn": None,
    "uid_field": "uid",
    "uri": "ldap://localhost:389",

}


@odm.model(index=False, store=False)
class Internal(odm.Model):
    enabled: bool = odm.Boolean()
    failure_ttl: int = odm.Integer()
    max_failures: int = odm.Integer()
    password_requirements: PasswordRequirement = odm.Compound(PasswordRequirement,
                                                              default=DEFAULT_PASSWORD_REQUIREMENTS)
    signup: Signup = odm.Compound(Signup, default=DEFAULT_SIGNUP)


DEFAULT_INTERNAL = {
    "enabled": True,
    "failure_ttl": 60,
    "max_failures": 5,
    "password_requirements": DEFAULT_PASSWORD_REQUIREMENTS,
    "signup": DEFAULT_SIGNUP
}


@odm.model(index=False, store=False)
class OAuthAutoProperty(odm.Model):
    field: str = odm.Keyword()
    pattern: str = odm.Keyword()
    type: str = odm.Enum(OAUTH_AUTO_PROPERTY_TYPE)
    value: str = odm.Keyword()


@odm.model(index=False, store=False)
class AppProvider(odm.Model):
    access_token_url: str = odm.Keyword()
    user_get: str = odm.Optional(odm.Keyword())
    group_get: str = odm.Optional(odm.Keyword())
    scope: str = odm.Keyword()
    client_id: str = odm.Optional(odm.Keyword())
    client_secret: str = odm.Optional(odm.Keyword())


@odm.model(index=False, store=False)
class OAuthProvider(odm.Model):
    auto_create: str = odm.Boolean(default=True)
    auto_sync: str = odm.Boolean(default=False)
    auto_properties: List[OAuthAutoProperty] = odm.List(odm.Compound(OAuthAutoProperty), default=[])
    app_provider: AppProvider = odm.Optional(odm.Compound(AppProvider))
    uid_randomize: str = odm.Boolean(default=False)
    uid_randomize_digits: str = odm.Integer(default=0)
    uid_randomize_delimiter: str = odm.Keyword(default="-")
    uid_regex: str = odm.Optional(odm.Keyword())
    uid_format: str = odm.Optional(odm.Keyword())
    client_id: str = odm.Optional(odm.Keyword())
    client_secret: str = odm.Optional(odm.Keyword())
    request_token_url: str = odm.Optional(odm.Keyword())
    request_token_params: str = odm.Optional(odm.Keyword())
    access_token_url: str = odm.Optional(odm.Keyword())
    access_token_params: str = odm.Optional(odm.Keyword())
    authorize_url: str = odm.Optional(odm.Keyword())
    authorize_params: str = odm.Optional(odm.Keyword())
    api_base_url: str = odm.Optional(odm.Keyword())
    client_kwargs: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()))
    jwks_uri: str = odm.Optional(odm.Keyword())
    uid_field: str = odm.Optional(odm.Keyword())
    user_get: str = odm.Optional(odm.Keyword())
    user_groups: str = odm.Optional(odm.Keyword())
    user_groups_data_field: str = odm.Optional(odm.Keyword())
    user_groups_name_field: str = odm.Optional(odm.Keyword())
    use_new_callback_format: str = odm.Boolean(default=False)


DEFAULT_OAUTH_PROVIDER_AZURE = {
    "access_token_url": 'https://login.microsoftonline.com/common/oauth2/token',
    "api_base_url": 'https://login.microsoft.com/common/',
    "authorize_url": 'https://login.microsoftonline.com/common/oauth2/authorize',
    "client_id": None,
    "client_secret": None,
    "client_kwargs": {"scope": "openid email profile"},
    "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    "user_get": "openid/userinfo"
}

DEFAULT_OAUTH_PROVIDER_GOOGLE = {
    "access_token_url": 'https://oauth2.googleapis.com/token',
    "api_base_url": 'https://openidconnect.googleapis.com/',
    "authorize_url": 'https://accounts.google.com/o/oauth2/v2/auth',
    "client_id": None,
    "client_secret": None,
    "client_kwargs": {"scope": "openid email profile"},
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
    "user_get": "v1/userinfo"
}

DEFAULT_OAUTH_PROVIDER_AUTH_ZERO = {
    "access_token_url": 'https://{TENANT}.auth0.com/oauth/token',
    "api_base_url": 'https://{TENANT}.auth0.com/',
    "authorize_url": 'https://{TENANT}.auth0.com/authorize',
    "client_id": None,
    "client_secret": None,
    "client_kwargs": {"scope": "openid email profile"},
    "jwks_uri": "https://{TENANT}.auth0.com/.well-known/jwks.json",
    "user_get": "userinfo"
}

DEFAULT_OAUTH_PROVIDERS = {
    'auth0': DEFAULT_OAUTH_PROVIDER_AUTH_ZERO,
    'azure_ad': DEFAULT_OAUTH_PROVIDER_AZURE,
    'google': DEFAULT_OAUTH_PROVIDER_GOOGLE,
}


@odm.model(index=False, store=False)
class OAuth(odm.Model):
    enabled: bool = odm.Boolean()
    gravatar_enabled: bool = odm.Boolean()
    providers: Dict[str, OAuthProvider] = odm.Mapping(odm.Compound(OAuthProvider), default=DEFAULT_OAUTH_PROVIDERS)


DEFAULT_OAUTH = {
    "enabled": False,
    "gravatar_enabled": True,
    "providers": DEFAULT_OAUTH_PROVIDERS
}


@odm.model(index=False, store=False)
class Auth(odm.Model):
    allow_2fa: bool = odm.Boolean()
    allow_apikeys: bool = odm.Boolean()
    allow_security_tokens: bool = odm.Boolean()
    internal: Internal = odm.Compound(Internal, default=DEFAULT_INTERNAL)
    ldap: LDAP = odm.Compound(LDAP, default=DEFAULT_LDAP)
    oauth: OAuth = odm.Compound(OAuth, default=DEFAULT_OAUTH)


DEFAULT_AUTH = {
    "allow_2fa": True,
    "allow_apikeys": True,
    "allow_security_tokens": True,
    "internal": DEFAULT_INTERNAL,
    "ldap": DEFAULT_LDAP,
    "oauth": DEFAULT_OAUTH
}


@odm.model(index=False, store=False)
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


@odm.model(index=False, store=False)
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
@odm.model(index=False, store=False)
class Expiry(odm.Model):
    # By turning on batch delete, delete queries are rounded by day therefore
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
@odm.model(index=False, store=False)
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

    # Drop a task altogether after this many seconds
    expire_after: int = odm.Integer()
    stale_after_seconds: int = odm.Integer()

    # How long should scores be cached in the ingester
    incomplete_expire_after_seconds: int = odm.Integer()
    incomplete_stale_after_seconds: int = odm.Integer()

    # How long can a queue get before we start dropping files
    sampling_at: Dict[str, int] = odm.Mapping(odm.Integer())
    max_inflight = odm.Integer()

    # How long are files results cached
    cache_dtl: int = odm.Integer()


DEFAULT_INGESTER = {
    'cache_dtl': 2,
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
    },
    'max_inflight': 500
}


@odm.model(index=False, store=False)
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


@odm.model(index=False, store=False)
class ESMetrics(odm.Model):
    hosts: str = odm.Optional(odm.List(odm.Keyword()))
    host_certificates: str = odm.Optional(odm.Keyword())
    warm: int = odm.Integer()
    cold: int = odm.Integer()
    delete: int = odm.Integer()
    unit = odm.Enum(['d', 'h', 'm'])


DEFAULT_ES_METRICS = {
    'hosts': None,
    'host_certificates': None,
    'warm': 2,
    'cold': 30,
    'delete': 90,
    'unit': 'd'
}


@odm.model(index=False, store=False)
class APMServer(odm.Model):
    server_url: str = odm.Optional(odm.Keyword())
    token: str = odm.Optional(odm.Keyword())


DEFAULT_APM_SERVER = {
    'server_url': None,
    'token': None
}


@odm.model(index=False, store=False)
class Metrics(odm.Model):
    apm_server: APMServer = odm.Compound(APMServer, default=DEFAULT_APM_SERVER)
    elasticsearch: ESMetrics = odm.Compound(ESMetrics, default=DEFAULT_ES_METRICS)
    export_interval: int = odm.Integer()
    redis: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP)


DEFAULT_METRICS = {
    'apm_server': DEFAULT_APM_SERVER,
    'elasticsearch': DEFAULT_ES_METRICS,
    'export_interval': 5,
    'redis': DEFAULT_REDIS_NP,
}


@odm.model(index=False, store=False)
class Redis(odm.Model):
    nonpersistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP)
    persistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_P)


DEFAULT_REDIS = {
    "nonpersistent": DEFAULT_REDIS_NP,
    "persistent": DEFAULT_REDIS_P
}


@odm.model(index=False, store=False)
class ScalerServiceDefaults(odm.Model):
    """A set of default values to be used running a service when no other value is set."""
    growth: int = odm.Integer()
    shrink: int = odm.Integer()
    backlog: int = odm.Integer()
    min_instances: int = odm.Integer()
    environment: List[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[])


@odm.model(index=False, store=False)
class Scaler(odm.Model):
    service_defaults: ScalerServiceDefaults = odm.Compound(ScalerServiceDefaults)
    # only available for docker hosts, not kubernetes
    cpu_overallocation: float = odm.Float(default=1)
    memory_overallocation: float = odm.Float(default=1)
    # Additional labels to be applied to deployments in kubernetes('=' delimited)
    additional_labels: List[str] = odm.Optional(odm.List(odm.Text()))


DEFAULT_SCALER = {
    'service_defaults': {
        'growth': 60,
        'shrink': 30,
        'backlog': 100,
        'min_instances': 0,
        'environment': [
            {'name': 'SERVICE_API_HOST', 'value': 'http://service-server:5003'},
            {'name': 'AL_SERVICE_TASK_LIMIT', 'value': 'inf'},
        ],
    }
}


@odm.model(index=False, store=False)
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


@odm.model(index=False, store=False)
class ILMParams(odm.Model):
    warm = odm.Integer()
    cold = odm.Integer()
    delete = odm.Integer()
    unit = odm.Enum(['d', 'h', 'm'])


DEFAULT_ILM_PARAMS = {
    "warm": 1,
    "cold": 15,
    "delete": 30,
    "unit":  "d"
}


@odm.model(index=False, store=False)
class ILMIndexes(odm.Model):
    alert = odm.Compound(ILMParams, default=DEFAULT_ILM_PARAMS)
    error = odm.Compound(ILMParams, default=DEFAULT_ILM_PARAMS)
    file = odm.Compound(ILMParams, default=DEFAULT_ILM_PARAMS)
    result = odm.Compound(ILMParams, default=DEFAULT_ILM_PARAMS)
    submission = odm.Compound(ILMParams, default=DEFAULT_ILM_PARAMS)


DEFAULT_ILM_INDEXES = {
    'alert': DEFAULT_ILM_PARAMS,
    'error': DEFAULT_ILM_PARAMS,
    'file': DEFAULT_ILM_PARAMS,
    'result': DEFAULT_ILM_PARAMS,
    'submission': DEFAULT_ILM_PARAMS,
}


@odm.model(index=False, store=False)
class ILM(odm.Model):
    enabled = odm.Boolean()
    days_until_archive = odm.Integer()
    indexes = odm.Compound(ILMIndexes, default=DEFAULT_ILM_INDEXES)


DEFAULT_ILM = {
    "days_until_archive": 5,
    "enabled": False,
    "indexes": DEFAULT_ILM_INDEXES
}


@odm.model(index=False, store=False)
class Datastore(odm.Model):
    hosts: List[str] = odm.List(odm.Keyword())
    ilm = odm.Compound(ILM, default=DEFAULT_ILM)
    type = odm.Enum({"elasticsearch"})


DEFAULT_DATASTORE = {
    "hosts": ["http://elastic:devpass@localhost"],
    "ilm": DEFAULT_ILM,
    "type": "elasticsearch",
}


@odm.model(index=False, store=False)
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


@odm.model(index=False, store=False)
class Filestore(odm.Model):
    cache: List[str] = odm.List(odm.Keyword())
    storage: List[str] = odm.List(odm.Keyword())


DEFAULT_FILESTORE = {
    "cache": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-cache&use_ssl=False"],
    "storage": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-storage&use_ssl=False"]
}


# This is the model definition for the logging block
@odm.model(index=False, store=False)
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
    syslog_port: int = odm.Integer()

    # How often should counters log their values (seconds)
    export_interval: int = odm.Integer()

    # Log in JSON format
    log_as_json: bool = odm.Boolean()

    # If set, core components will touch this path regularly to tell the container
    # environment it is healthy
    heartbeat_file: str = odm.Optional(odm.Keyword())


DEFAULT_LOGGING = {
    "log_directory": "/var/log/assemblyline/",
    "log_as_json": True,
    "log_level": "INFO",
    "log_to_console": True,
    "log_to_file": False,
    "log_to_syslog": False,
    "syslog_host": "localhost",
    "syslog_port": 514,
    "export_interval": 5,
    "heartbeat_file": "/tmp/heartbeat"
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
@odm.model(index=False, store=False)
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
    # Substitution variables for image paths (for custom registry support)
    image_variables: Dict[str, str] = odm.Mapping(odm.Keyword(default=''))
    # Default update channel to be used for new services
    preferred_update_channel: str = odm.Keyword()


DEFAULT_SERVICES = {
    "categories": SERVICE_CATEGORIES,
    "default_timeout": 60,
    "min_service_workers": 0,
    "stages": SERVICE_STAGES,
    "image_variables": {},
    "preferred_update_channel": "stable"
}


# This is the model definition for the System block
@odm.model(index=False, store=False)
class System(odm.Model):
    # Module path to the assemblyline constants
    constants: str = odm.Keyword()
    # Organisation acronym used for signatures
    organisation: str = odm.Text()
    # Type of system (production, staging, development)
    type: str = odm.Enum(values=['production', 'staging', 'development'])


DEFAULT_SYSTEM = {
    "constants": "assemblyline.common.constants",
    "organisation": "ACME",
    "type": 'production'
}


# This is the model definition for the System block
@odm.model(index=False, store=False)
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
@odm.model(index=False, store=False)
class UI(odm.Model):
    # Allow to user to download raw files
    allow_raw_downloads: bool = odm.Boolean()
    # Allow file submissions via url
    allow_url_submissions: bool = odm.Boolean()
    # Should API calls be audited and saved to a separate log file?
    audit: bool = odm.Boolean()
    # Banner message display on the main page (format: {<language_code>: message})
    banner: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()))
    # Banner message display on the main page (format: {<language_code>: message})
    banner_level: str = odm.Enum(values=["info", "warning", "success", "error"])
    # Turn on debugging
    debug: bool = odm.Boolean()
    # Which encoding will be used
    download_encoding = odm.Enum(values=["raw", "cart"])
    # Assemblyline admins email address
    email: str = odm.Optional(odm.Email())
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
    # List of admins to notify when a user gets locked out
    tos_lockout_notify: bool = odm.Optional(odm.List(odm.Keyword()))
    # Headers that will be used by the url_download method
    url_submission_headers: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()))
    # Proxy that will be used by the url_download method
    url_submission_proxies: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()))
    # Validate if the session ip matches the ip the session was created from
    validate_session_ip: bool = odm.Boolean()
    # Validate if the session useragent matches the useragent the session was created with
    validate_session_useragent: bool = odm.Boolean()


DEFAULT_UI = {
    "allow_raw_downloads": True,
    "allow_url_submissions": True,
    "audit": True,
    "banner": None,
    "banner_level": 'info',
    "debug": False,
    "download_encoding": "cart",
    "email": None,
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
    "tos_lockout_notify": None,
    "url_submission_headers": {},
    "url_submission_proxies": {},
    "validate_session_ip": True,
    "validate_session_useragent": True,
}


# Options regarding all submissions, regardless of their input method
@odm.model(index=False, store=False)
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
        'technique.obfuscation',
    ],
    'behavior': [
        'file.behavior'
    ],
    'ioc': [
        'network.email.address',
        'network.static.ip',
        'network.static.domain',
        'network.static.uri',
        'network.dynamic.ip',
        'network.dynamic.domain',
        'network.dynamic.uri',

    ]
}


# Options regarding all submissions, regardless of their input method
@odm.model(index=False, store=False)
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
    'dtl': 30,
    'max_extraction_depth': 6,
    'max_file_size': 104857600,
    'max_metadata_length': 4096,
    'tag_types': DEFAULT_TAG_TYPES
}


@odm.model(index=False, store=False)
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


if __name__ == "__main__":
    # When executed, the config model will print the default values of the configuration
    from pprint import pprint
    pprint(DEFAULT_CONFIG)
