from typing import Any, Dict, List

from assemblyline import odm
from assemblyline.common.constants import PRIORITIES
from assemblyline.common.forge import get_classification
from assemblyline.odm.models.service import EnvironmentVariable
from assemblyline.odm.models.service_delta import DockerConfigDelta
from assemblyline.odm.models.submission import DEFAULT_SRV_SEL, ServiceSelection

AUTO_PROPERTY_TYPE = ['access', 'classification', 'type', 'role', 'remove_role', 'group',
                      'multi_group', 'api_quota', 'api_daily_quota', 'submission_quota',
                      'submission_async_quota', 'submission_daily_quota']
DEFAULT_EMAIL_FIELDS = ['email', 'emails', 'extension_selectedEmailAddress', 'otherMails', 'preferred_username', 'upn']

DEFAULT_DAILY_API_QUOTA = 0
DEFAULT_API_QUOTA = 10
DEFAULT_DAILY_SUBMISSION_QUOTA = 0
DEFAULT_SUBMISSION_QUOTA = 5
DEFAULT_ASYNC_SUBMISSION_QUOTA = 0

Classification = get_classification()


@odm.model(index=False, store=False, description="Password Requirement")
class PasswordRequirement(odm.Model):
    lower: bool = odm.Boolean(description="Password must contain lowercase letters")
    number: bool = odm.Boolean(description="Password must contain numbers")
    special: bool = odm.Boolean(description="Password must contain special characters")
    upper: bool = odm.Boolean(description="Password must contain uppercase letters")
    min_length: int = odm.Integer(description="Minimum password length")


DEFAULT_PASSWORD_REQUIREMENTS = {
    "lower": False,
    "number": False,
    "special": False,
    "upper": False,
    "min_length": 12
}


@odm.model(index=False, store=False,
           description="Configuration block for [GC Notify](https://notification.canada.ca/) signup and password reset")
class Notify(odm.Model):
    base_url: str = odm.Optional(odm.Keyword(), description="Base URL")
    api_key: str = odm.Optional(odm.Keyword(), description="API key")
    registration_template: str = odm.Optional(odm.Keyword(), description="Registration template")
    password_reset_template: str = odm.Optional(odm.Keyword(), description="Password reset template")
    authorization_template: str = odm.Optional(odm.Keyword(), description="Authorization template")
    activated_template: str = odm.Optional(odm.Keyword(), description="Activated Template")


DEFAULT_NOTIFY = {
    "base_url": None,
    "api_key": None,
    "registration_template": None,
    "password_reset_template": None,
    "authorization_template": None,
    "activated_template": None,
}


@odm.model(index=False, store=False, description="Configuration block for SMTP signup and password reset")
class SMTP(odm.Model):
    from_adr: str = odm.Optional(odm.Keyword(), description="Email address used for sender")
    host: str = odm.Optional(odm.Keyword(), description="SMTP host")
    password: str = odm.Optional(odm.Keyword(), description="Password for SMTP server")
    port: int = odm.Integer(description="Port of SMTP server")
    tls: bool = odm.Boolean(description="Should we communicate with SMTP server via TLS?")
    user: str = odm.Optional(odm.Keyword(), description="User to authenticate to the SMTP server")


DEFAULT_SMTP = {
    "from_adr": None,
    "host": None,
    "password": None,
    "port": 587,
    "tls": True,
    "user": None
}


@odm.model(index=False, store=False, description="Signup Configuration")
class Signup(odm.Model):
    enabled: bool = odm.Boolean(description="Can a user automatically signup for the system")
    smtp: SMTP = odm.Compound(SMTP, default=DEFAULT_SMTP, description="Signup via SMTP")
    notify: Notify = odm.Compound(Notify, default=DEFAULT_NOTIFY, description="Signup via GC Notify")
    valid_email_patterns: List[str] = odm.List(
        odm.Keyword(),
        description="Email patterns that will be allowed to automatically signup for an account")


DEFAULT_SIGNUP = {
    "enabled": False,
    "notify": DEFAULT_NOTIFY,
    "smtp": DEFAULT_SMTP,
    "valid_email_patterns": [".*", ".*@localhost"]
}


@odm.model(index=False, store=False)
class AutoProperty(odm.Model):
    field: str = odm.Keyword(description="Field to apply `pattern` to")
    pattern: str = odm.Keyword(description="Regex pattern for auto-prop assignment")
    type: str = odm.Enum(AUTO_PROPERTY_TYPE, description="Type of property assignment on pattern match")
    value: List[str] = odm.List(odm.Keyword(), auto=True, default=[], description="Assigned property value")


@odm.model(index=False, store=False, description="LDAP Configuration")
class LDAP(odm.Model):
    enabled: bool = odm.Boolean(description="Should LDAP be enabled or not?")
    admin_dn: str = odm.Optional(odm.Keyword(), description="DN of the group or the user who will get admin privileges")
    bind_user: str = odm.Optional(odm.Keyword(), description="User use to query the LDAP server")
    bind_pass: str = odm.Optional(odm.Keyword(), description="Password used to query the LDAP server")
    auto_create: bool = odm.Boolean(description="Auto-create users if they are missing")
    auto_sync: bool = odm.Boolean(description="Should we automatically sync with LDAP server on each login?")
    auto_properties: List[AutoProperty] = odm.List(odm.Compound(AutoProperty), default=[],
                                                   description="Automatic role and classification assignments")
    base: str = odm.Keyword(description="Base DN for the users")
    classification_mappings: Dict[str, str] = odm.Any(description="Classification mapping")
    email_field: str = odm.Keyword(description="Name of the field containing the email address")
    group_lookup_query: str = odm.Keyword(description="How the group lookup is queried")
    group_lookup_with_uid: bool = odm.Boolean(description="Use username/uid instead of dn for group lookup")
    image_field: str = odm.Keyword(description="Name of the field containing the user's avatar")
    image_format: str = odm.Keyword(description="Type of image used to store the avatar")
    name_field: str = odm.Keyword(description="Name of the field containing the user's name")
    signature_importer_dn: str = odm.Optional(
        odm.Keyword(),
        description="DN of the group or the user who will get signature_importer role")
    signature_manager_dn: str = odm.Optional(
        odm.Keyword(),
        description="DN of the group or the user who will get signature_manager role")
    uid_field: str = odm.Keyword(description="Field name for the UID")
    uri: str = odm.Keyword(description="URI to the LDAP server")


DEFAULT_LDAP = {
    "enabled": False,
    "bind_user": None,
    "bind_pass": None,
    "auto_create": True,
    "auto_sync": True,
    "auto_properties": [],
    "base": "ou=people,dc=assemblyline,dc=local",
    "email_field": "mail",
    "group_lookup_query": "(&(objectClass=Group)(member=%s))",
    "group_lookup_with_uid": False,
    "image_field": "jpegPhoto",
    "image_format": "jpeg",
    "name_field": "cn",
    "uid_field": "uid",
    "uri": "ldap://localhost:389",

    # Deprecated
    "admin_dn": None,
    "classification_mappings": {},
    "signature_importer_dn": None,
    "signature_manager_dn": None,
}


@odm.model(index=False, store=False, description="Internal Authentication Configuration")
class Internal(odm.Model):
    enabled: bool = odm.Boolean(description="Internal authentication allowed?")
    failure_ttl: int = odm.Integer(description="How long to wait after `max_failures` before re-attempting login?")
    max_failures: int = odm.Integer(description="Maximum number of fails allowed before timeout")
    password_requirements: PasswordRequirement = odm.Compound(PasswordRequirement,
                                                              default=DEFAULT_PASSWORD_REQUIREMENTS,
                                                              description="Password requirements")
    signup: Signup = odm.Compound(Signup, default=DEFAULT_SIGNUP, description="Signup method")


DEFAULT_INTERNAL = {
    "enabled": True,
    "failure_ttl": 60,
    "max_failures": 5,
    "password_requirements": DEFAULT_PASSWORD_REQUIREMENTS,
    "signup": DEFAULT_SIGNUP
}


@odm.model(index=False, store=False, description="App provider")
class AppProvider(odm.Model):
    access_token_url: str = odm.Keyword(description="URL used to get the access token")
    user_get: str = odm.Optional(odm.Keyword(), description="Path from the base_url to fetch the user info")
    group_get: str = odm.Optional(odm.Keyword(), description="Path from the base_url to fetch the group info")
    scope: str = odm.Keyword()
    client_id: str = odm.Optional(odm.Keyword(), description="ID of your application to authenticate to the OAuth")
    client_secret: str = odm.Optional(odm.Keyword(),
                                      description="Password to your application to authenticate to the OAuth provider")


@odm.model(index=False, store=False, description="OAuth Provider Configuration")
class OAuthProvider(odm.Model):
    auto_create: bool = odm.Boolean(default=True, description="Auto-create users if they are missing")
    auto_sync: bool = odm.Boolean(default=False, description="Should we automatically sync with OAuth provider?")
    auto_properties: List[AutoProperty] = odm.List(odm.Compound(AutoProperty), default=[],
                                                   description="Automatic role and classification assignments")
    app_provider: AppProvider = odm.Optional(odm.Compound(AppProvider))
    uid_randomize: bool = odm.Boolean(default=False,
                                      description="Should we generate a random username for the authenticated user?")
    uid_randomize_digits: int = odm.Integer(default=0,
                                            description="How many digits should we add at the end of the username?")
    uid_randomize_delimiter: str = odm.Keyword(default="-",
                                               description="What is the delimiter used by the random name generator?")
    uid_regex: str = odm.Optional(
        odm.Keyword(),
        description="Regex used to parse an email address and capture parts to create a user ID out of it")
    uid_format: str = odm.Optional(odm.Keyword(),
                                   description="Format of the user ID based on the captured parts from the regex")
    client_id: str = odm.Optional(odm.Keyword(),
                                  description="ID of your application to authenticate to the OAuth provider")
    client_secret: str = odm.Optional(odm.Keyword(),
                                      description="Password to your application to authenticate to the OAuth provider")
    redirect_uri: str = odm.Optional(odm.Keyword(),
                                     description="URI to redirect to after authentication with OAuth provider")
    request_token_url: str = odm.Optional(odm.Keyword(), description="URL to request token")
    request_token_params: Dict[str, str] = odm.Optional(
        odm.Mapping(odm.Keyword()), description="Parameters to request token")
    access_token_url: str = odm.Optional(odm.Keyword(), description="URL to get access token")
    access_token_params: Dict[str, str] = odm.Optional(odm.Mapping(
        odm.Keyword()), description="Parameters to get access token")
    authorize_url: str = odm.Optional(odm.Keyword(), description="URL used to authorize access to a resource")
    authorize_params: Dict[str, str] = odm.Optional(odm.Mapping(
        odm.Keyword()), description="Parameters used to authorize access to a resource")
    api_base_url: str = odm.Optional(odm.Keyword(), description="Base URL for downloading the user's and groups info")
    client_kwargs: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()),
                                                 description="Keyword arguments passed to the different URLs")
    jwks_uri: str = odm.Optional(odm.Keyword(), description="URL used to verify if a returned JWKS token is valid")
    jwt_token_alg: str = odm.Keyword(default="RS256", description="Algorythm use the validate JWT OBO tokens")
    uid_field: str = odm.Optional(odm.Keyword(), description="Name of the field that will contain the user ID")
    user_get: str = odm.Optional(odm.Keyword(), description="Path from the base_url to fetch the user info")
    user_groups: str = odm.Optional(odm.Keyword(), description="Path from the base_url to fetch the group info")
    user_groups_data_field: str = odm.Optional(
        odm.Keyword(),
        description="Field return by the group info API call that contains the list of groups")
    user_groups_name_field: str = odm.Optional(
        odm.Keyword(),
        description="Name of the field in the list of groups that contains the name of the group")
    use_new_callback_format: bool = odm.Boolean(default=False, description="Should we use the new callback method?")
    allow_external_tokens: bool = odm.Boolean(
        default=False, description="Should token provided to the login API directly be use for authentication?")
    external_token_alternate_audiences: List[str] = odm.List(
        odm.Keyword(), default=[], description="List of valid alternate audiences for the external token.")
    email_fields: List[str] = odm.List(odm.Keyword(), default=DEFAULT_EMAIL_FIELDS,
                                       description="List of fields in the claim to get the email from")
    username_field: str = odm.Keyword(default='uname', description="Name of the field that will contain the username")
    validate_token_with_secret: bool = odm.Boolean(
        default=False, description="Should we send the client secret while validating the access token?")
    identity_id_field: str = odm.Keyword(default='oid', description="Field to fetch the managed identity ID from.")


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


@odm.model(index=False, store=False, description="OAuth Configuration")
class OAuth(odm.Model):
    enabled: bool = odm.Boolean(description="Enable use of OAuth?")
    gravatar_enabled: bool = odm.Boolean(description="Enable gravatar?")
    providers: Dict[str, OAuthProvider] = odm.Mapping(odm.Compound(OAuthProvider),
                                                      default=DEFAULT_OAUTH_PROVIDERS,
                                                      description="OAuth provider configuration")


DEFAULT_OAUTH = {
    "enabled": False,
    "gravatar_enabled": True,
    "providers": DEFAULT_OAUTH_PROVIDERS
}


DEFAULT_SAML_SETTINGS = {
    "strict": False,
    "debug": False,
    "sp": {
        "entity_id": "https://assemblyline/sp",
        "assertion_consumer_service": {
            "url": "https://localhost/api/v4/auth/saml/acs/",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    },
    "idp": {
        "entity_id": "https://mocksaml.com/api/saml/metadata",
        "single_sign_on_service": {
            "url": "https://mocksaml.com/api/saml/sso",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
    },
}

DEFAULT_SAML_ATTRIBUTES = {
    "email_attribute": "email",
    "fullname_attribute": "name",
    "groups_attribute": "groups",
    "roles_attribute": "roles",
    "group_type_mapping": {},
}


@odm.model(index=False, store=False, description="SAML Assertion Consumer Service")
class SAMLAssertionConsumerService(odm.Model):
    url: str = odm.Keyword(description="URL")
    binding: str = odm.Keyword(description="Binding", default="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")


@odm.model(index=False, store=False, description="SAML Single Sign On Service")
class SAMLSingleSignOnService(odm.Model):
    url: str = odm.Keyword(description="URL")
    binding: str = odm.Keyword(description="Binding", default="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")


@odm.model(index=False, store=False, description="SAML Attribute")
class SAMLRequestedAttribute(odm.Model):
    name: str = odm.Keyword(description="Name")
    is_required: bool = odm.Boolean(description="Is required?", default=False)
    name_format: str = odm.Keyword(description="Name Format",
                                   default="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
    friendly_name: str = odm.Keyword(description="Friendly Name", default="")
    attribute_value: List[str] = odm.List(odm.Keyword(), description="Attribute Value", default=[])


@odm.model(index=False, store=False, description="SAML Attribute Consuming Service")
class SAMLAttributeConsumingService(odm.Model):
    service_name: str = odm.Keyword(description="Service Name")
    service_description: str = odm.Keyword(description="Service Description")
    requested_attributes: List[SAMLRequestedAttribute] = odm.List(
        odm.Compound(SAMLRequestedAttribute),
        description="Requested Attributes", default=[])


@odm.model(index=False, store=False, description="SAML Service Provider")
class SAMLServiceProvider(odm.Model):
    entity_id: str = odm.Keyword(description="Entity ID")
    assertion_consumer_service: SAMLAssertionConsumerService = odm.Compound(
        SAMLAssertionConsumerService, description="Assertion Consumer Service")
    attribute_consuming_service: SAMLAttributeConsumingService = odm.Optional(
        odm.Compound(SAMLAttributeConsumingService), description="Attribute Consuming Service")
    name_id_format: str = odm.Keyword(description="Name ID Format",
                                      default="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
    x509cert: str = odm.Optional(odm.Keyword(), description="X509 Certificate")
    private_key: str = odm.Optional(odm.Keyword(), description="Private Key")


@odm.model(index=False, store=False, description="SAML Identity Provider")
class SAMLIdentityProvider(odm.Model):
    entity_id: str = odm.Keyword(description="Entity ID")
    single_sign_on_service: SAMLSingleSignOnService = odm.Compound(
        SAMLSingleSignOnService, description="Single Sign On Service")
    x509cert: str = odm.Optional(odm.Keyword(), description="X509 Certificate")


@odm.model(index=False, store=False, description="SAML Contact Entry")
class SAMLContactPerson(odm.Model):
    given_name: str = odm.Keyword(description="Given Name")
    email_address: str = odm.Keyword(description="Email Address")


@odm.model(index=False, store=False, description="SAML Contacts")
class SAMLContacts(odm.Model):
    technical: SAMLContactPerson = odm.Compound(SAMLContactPerson, description="Technical Contact")
    support: SAMLContactPerson = odm.Compound(SAMLContactPerson, description="Support Contact")


@odm.model(index=False, store=False, description="SAML Organization")
class SAMLOrganization(odm.Model):
    name: str = odm.Keyword(description="Name")
    display_name: str = odm.Keyword(description="Display Name")
    url: str = odm.Keyword(description="URL")


@odm.model(index=False, store=False, description="SAML Security")
class SAMLSecurity(odm.Model):
    name_id_encrypted: bool = odm.Optional(odm.Boolean(), description="Name ID Encrypted")
    authn_requests_signed: bool = odm.Optional(odm.Boolean(), description="Authn Requests Signed")
    logout_request_signed: bool = odm.Optional(odm.Boolean(), description="Logout Request Signed")
    logout_response_signed: bool = odm.Optional(odm.Boolean(), description="Logout Response Signed")
    sign_metadata: bool = odm.Optional(odm.Boolean(), description="Sign Metadata")
    want_messages_signed: bool = odm.Optional(odm.Boolean(), description="Want Messages Signed")
    want_assertions_signed: bool = odm.Optional(odm.Boolean(), description="Want Assertions Signed")
    want_assertions_encrypted: bool = odm.Optional(odm.Boolean(), description="Want Assertions Encrypted")
    want_name_id: bool = odm.Optional(odm.Boolean(), description="Want Name ID")
    want_name_id_encrypted: bool = odm.Optional(odm.Boolean(), description="Want Name ID Encrypted")
    want_attribute_statement: bool = odm.Optional(odm.Boolean(), description="Want Attribute Statement")
    requested_authn_context: bool = odm.Optional(odm.Boolean(), description="Requested Authn Context")
    requested_authn_context_comparison: str = odm.Optional(
        odm.Keyword(), description="Requested Authn Context Comparison")
    fail_on_authn_context_mismatch: bool = odm.Optional(odm.Boolean(), description="Fail On Authn Context Mismatch")
    metadata_valid_until: str = odm.Optional(odm.Keyword(), description="Metadata Valid Until")
    metadata_cache_duration: str = odm.Optional(odm.Keyword(), description="Metadata Cache Duration")
    allow_single_label_domains: bool = odm.Optional(odm.Boolean(), description="Allow Single Label Domains")
    signature_algorithm: str = odm.Optional(odm.Keyword(), description="Signature Algorithm")
    digest_algorithm: str = odm.Optional(odm.Keyword(), description="Digest Algorithm")
    allow_repeat_attribute_name: bool = odm.Optional(odm.Boolean(), description="Allow Repeat Attribute Name")
    reject_deprecated_algorithm: bool = odm.Optional(odm.Boolean(), description="Reject Deprecated Algorithm")


@odm.model(index=False, store=False, description="SAML Settings")
class SAMLSettings(odm.Model):
    strict: bool = odm.Boolean(description="Should we be strict in our SAML checks?", default=True)
    debug: bool = odm.Boolean(description="Should we be in debug mode?", default=False)
    sp: SAMLServiceProvider = odm.Compound(SAMLServiceProvider, description="SP settings")
    idp: SAMLIdentityProvider = odm.Compound(SAMLIdentityProvider, description="IDP settings")
    security: SAMLSecurity = odm.Optional(odm.Compound(SAMLSecurity), description="Security settings")
    contact_person: SAMLContacts = odm.Optional(odm.Compound(SAMLContacts), description="Contact settings")
    organization: Dict[str, SAMLOrganization] = odm.Optional(odm.Mapping(
        odm.Compound(SAMLOrganization)), description="Organization settings")


@odm.model(index=False, store=False, description="SAML Attributes")
class SAMLAttributes(odm.Model):
    username_attribute: str = odm.Optional(
        odm.Keyword(default="uid"),
        description="SAML attribute name for AL username")
    email_attribute: str = odm.Keyword(description="SAML attribute name for a user's email address ", default="email")
    fullname_attribute: str = odm.Keyword(description="SAML attribute name for a user's first name", default="name")
    groups_attribute: str = odm.Keyword(description="SAML attribute name for the groups", default="groups")
    roles_attribute: str = odm.Keyword(description="SAML attribute name for the roles", default="roles")
    group_type_mapping: Dict[str, str] = odm.Mapping(
        odm.Keyword(), description="SAML group to role mapping", default={})


@odm.model(index=False, store=False, description="SAML Configuration")
class SAML(odm.Model):
    enabled: bool = odm.Boolean(description="Enable use of SAML?")
    auto_create: bool = odm.Boolean(description="Auto-create users if they are missing", default=True)
    auto_sync: bool = odm.Boolean(
        description="Should we automatically sync with SAML server on each login?", default=True)
    lowercase_urlencoding: bool = odm.Boolean(
        description="Enable lowercase encoding if using ADFS as IdP", default=False)
    attributes: SAMLAttributes = odm.Compound(
        SAMLAttributes, default=DEFAULT_SAML_ATTRIBUTES, description="SAML attributes")
    settings: SAMLSettings = odm.Compound(SAMLSettings, default=DEFAULT_SAML_SETTINGS,
                                          description="SAML settings method")


DEFAULT_SAML = {
    "enabled": False,
    "auto_create": True,
    "auto_sync": True,
    "lowercase_urlencoding": False,
    "attributes": DEFAULT_SAML_ATTRIBUTES,
    "settings": DEFAULT_SAML_SETTINGS
}


@odm.model(index=False, store=False, description="Authentication Methods")
class Auth(odm.Model):
    allow_2fa: bool = odm.Boolean(description="Allow 2FA?")
    allow_apikeys: bool = odm.Boolean(description="Allow API keys?")
    apikey_max_dtl: int = odm.Optional(odm.Integer(description="Number of days apikey can live for."))
    allow_extended_apikeys: bool = odm.Boolean(description="Allow extended API keys?")
    allow_security_tokens: bool = odm.Boolean(description="Allow security tokens?")
    internal: Internal = odm.Compound(Internal, default=DEFAULT_INTERNAL,
                                      description="Internal authentication settings")
    ldap: LDAP = odm.Compound(LDAP, default=DEFAULT_LDAP, description="LDAP settings")
    oauth: OAuth = odm.Compound(OAuth, default=DEFAULT_OAUTH, description="OAuth settings")
    saml: SAML = odm.Compound(SAML, default=DEFAULT_SAML, description="SAML settings")


DEFAULT_AUTH = {
    "allow_2fa": True,
    "allow_apikeys": True,
    "apikey_max_dtl": None,
    "allow_extended_apikeys": True,
    "allow_security_tokens": True,
    "internal": DEFAULT_INTERNAL,
    "ldap": DEFAULT_LDAP,
    "oauth": DEFAULT_OAUTH,
    "saml": DEFAULT_SAML
}


@odm.model(index=False, store=False, description="Alerter Configuration")
class Alerter(odm.Model):
    alert_ttl: int = odm.integer(description="Time to live (days) for an alert in the system")
    constant_alert_fields: List[str] = odm.sequence(
        odm.keyword(), default=[],
        description="List of fields that should not change during an alert update",
        deprecation="This behavior is no longer configurable")
    constant_ignore_keys: List[str] = odm.sequence(
        odm.keyword(), default=[],
        description="List of keys to ignore in the constant alert fields.",
        deprecation="This behavior is no longer configurable")
    default_group_field: str = odm.keyword(description="Default field used for alert grouping view")
    delay: int = odm.integer(
        description="Time in seconds that we give extended scans and workflow to complete their work "
                    "before we start showing alerts in the alert viewer.")
    filtering_group_fields: List[str] = odm.sequence(
        odm.keyword(),
        description="List of group fields that when selected will ignore certain alerts where this field is missing.")
    non_filtering_group_fields: List[str] = odm.sequence(
        odm.keyword(), description="List of group fields that are sure to be present in all alerts.")
    process_alert_message: str = odm.keyword(
        description="Python path to the function that will process an alert message.")
    threshold: int = odm.integer(description="Minimum score to reach for a submission to be considered an alert.")


DEFAULT_ALERTER = {
    "alert_ttl": 90,
    "constant_alert_fields": [],
    "constant_ignore_keys": [],
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
    "threshold": 500
}


@odm.model(index=False, store=False, description="Dispatcher Configuration")
class Dispatcher(odm.Model):
    timeout: float = odm.Integer(
        description="Time between re-dispatching attempts, as long as some action (submission or any task completion) "
        "happens before this timeout ends, the timeout resets.")
    max_inflight: int = odm.Integer(description="Maximum submissions allowed to be in-flight")


DEFAULT_DISPATCHER = {
    "timeout": 15*60,
    "max_inflight": 1000
}


# Configuration options regarding data expiry
@odm.model(index=False, store=False)
class Expiry(odm.Model):
    batch_delete = odm.Boolean(
        description="Perform expiry in batches?<br>"
        "Delete queries are rounded by day therefore all delete operation happen at the same time at midnight")
    delay = odm.Integer(description="Delay, in hours, that will be applied to the expiry query so we can keep"
                        "data longer then previously set or we can offset deletion during non busy hours")
    delete_storage = odm.Boolean(description="Should we also cleanup the file storage?")
    sleep_time = odm.Integer(description="Time, in seconds, to sleep in between each expiry run")
    workers = odm.Integer(description="Number of concurrent workers")
    delete_workers = odm.Integer(description="Worker processes for file storage deletes.")
    iteration_max_tasks = odm.Integer(description="How many query chunks get run per iteration.")
    delete_batch_size = odm.Integer(max=10000, description="How large a batch get deleted per iteration.")
    safelisted_tag_dtl = odm.Integer(min=0, description="The default period, in days, before tags expire from Safelist")
    badlisted_tag_dtl = odm.Integer(min=0, description="The default period, in days, before tags expire from Badlist")


DEFAULT_EXPIRY = {
    'batch_delete': False,
    'delay': 0,
    'delete_storage': True,
    'sleep_time': 15,
    'workers': 20,
    'delete_workers': 2,
    'iteration_max_tasks': 50,
    'delete_batch_size': 2000,
    'safelisted_tag_dtl': 0,
    'badlisted_tag_dtl': 0
}


@odm.model(index=False, store=False, description="Ingester Configuration")
class Ingester(odm.Model):
    always_create_submission: bool = odm.Boolean(default=False,
                                                 description="Always create submissions even on cache hit?")
    default_user: str = odm.Keyword(description="Default user for bulk ingestion and unattended submissions")
    default_services: List[str] = odm.List(odm.Keyword(), description="Default service selection")
    default_resubmit_services: List[str] = odm.List(odm.Keyword(),
                                                    description="Default service selection for resubmits")
    description_prefix: str = odm.Keyword(
        description="A prefix for descriptions. When a description is automatically generated, it will be "
                    "the hash prefixed by this string")
    is_low_priority: str = odm.Keyword(
        description="Path to a callback function filtering ingestion tasks that should have their priority "
                    "forcefully reset to low")
    get_whitelist_verdict: str = odm.Keyword()
    whitelist: str = odm.Keyword()
    default_max_extracted: int = odm.Integer(
        description="How many extracted files may be added to a Submission. Overrideable via submission parameters.")
    default_max_supplementary: int = odm.Integer(
        description="How many supplementary files may be added to a Submission. Overrideable via submission parameters")
    expire_after: int = odm.Integer(description="Period, in seconds, in which a task should be expired")
    stale_after_seconds: int = odm.Integer(description="Drop a task altogether after this many seconds")
    incomplete_expire_after_seconds: int = odm.Integer(description="How long should scores be kept before expiry")
    incomplete_stale_after_seconds: int = odm.Integer(description="How long should scores be cached in the ingester")
    sampling_at: Dict[str, int] = odm.Mapping(odm.Integer(),
                                              description="Thresholds at certain buckets before sampling")
    max_inflight = odm.Integer(description="How long can a queue get before we start dropping files")
    cache_dtl: int = odm.Integer(min=0, description="How long are files results cached")


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


@odm.model(index=False, store=False, description="Redis Service configuration")
class RedisServer(odm.Model):
    host: str = odm.Keyword(description="Hostname of Redis instance")
    port: int = odm.Integer(description="Port of Redis instance")


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
    hosts: List[str] = odm.Optional(odm.List(odm.Keyword()), description="Elasticsearch hosts")
    host_certificates: str = odm.Optional(odm.Keyword(), description="Host certificates")
    warm = odm.Integer(description="How long, per unit of time, should a document remain in the 'warm' tier?")
    cold = odm.Integer(description="How long, per unit of time, should a document remain in the 'cold' tier?")
    delete = odm.Integer(description="How long, per unit of time, should a document remain before being deleted?")
    unit = odm.Enum(['d', 'h', 'm'], description="Unit of time used by `warm`, `cold`, `delete` phases")


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
    server_url: str = odm.Optional(odm.Keyword(), description="URL to API server")
    token: str = odm.Optional(odm.Keyword(), description="Authentication token for server")


DEFAULT_APM_SERVER = {
    'server_url': None,
    'token': None
}


@odm.model(index=False, store=False, description="Metrics Configuration")
class Metrics(odm.Model):
    apm_server: APMServer = odm.Compound(APMServer, default=DEFAULT_APM_SERVER, description="APM server configuration")
    elasticsearch: ESMetrics = odm.Compound(ESMetrics, default=DEFAULT_ES_METRICS,
                                            description="Where to export metrics?")
    export_interval: int = odm.Integer(description="How often should we be exporting metrics?")
    redis: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP, description="Redis for Dashboard metrics")


DEFAULT_METRICS = {
    'apm_server': DEFAULT_APM_SERVER,
    'elasticsearch': DEFAULT_ES_METRICS,
    'export_interval': 5,
    'redis': DEFAULT_REDIS_NP,
}


@odm.model(index=False, store=False, description="Malware Archive Configuration")
class ArchiverMetadata(odm.Model):
    default = odm.Optional(odm.Keyword(description="Default value for the metadata"))
    editable = odm.Boolean(default=False, description="Can the user provide a custom value")
    values = odm.List(odm.Keyword(), default=[], description="List of possible values to pick from")


EXEMPLE_ARCHIVER_METADATA = {
    'rationale': {
        'default': "File is malicious",
        'editable': True,
        'values': ["File is malicious", "File is interesting", "I just feel like keeping this..."]
    }
}


@odm.model(index=False, store=False, description="Named Value")
class NamedValue(odm.Model):
    name = odm.Keyword(description="Name")
    value = odm.Keyword(description="Value")


@odm.model(index=False, store=False, description="Webhook Configuration")
class Webhook(odm.Model):
    password = odm.Optional(odm.Keyword(default=""), description="Password used to authenticate with source")
    ca_cert = odm.Optional(odm.Keyword(default=""), description="CA cert for source")
    ssl_ignore_errors = odm.Boolean(default=False, description="Ignore SSL errors when reaching out to source?")
    proxy = odm.Optional(odm.Keyword(default=""), description="Proxy server for source")
    method = odm.Keyword(default='POST', description="HTTP method used to access webhook")
    uri = odm.Keyword(description="URI to source")
    username = odm.Optional(odm.Keyword(default=""), description="Username used to authenticate with source")
    headers = odm.List(odm.Compound(NamedValue), default=[], description="Headers")
    retries = odm.Integer(default=3)


DEFAULT_ARCHIVER_WEBHOOK = {
    'password': None,
    'ca_cert': None,
    'ssl_ignore_errors': False,
    'proxy': None,
    'method': "POST",
    'uri': "https://archiving-hook",
    'username': None,
    'headers': [],
    'retries': 3
}


@odm.model(index=False, store=False, description="Malware Archive Configuration")
class Archiver(odm.Model):
    alternate_dtl: int = odm.Integer(description="Alternate number of days to keep the data in the "
                                                 "malware archive. (0: Disabled, will keep data forever)")
    metadata: Dict = odm.Mapping(
        odm.Compound(ArchiverMetadata),
        description="Proxy configuration that is passed to Python Requests",
        deprecation="The configuration for the archive metadata validation and requirements has moved to"
                    "`submission.metadata.archive`.")
    minimum_required_services: List[str] = odm.List(
        odm.keyword(),
        default=[],
        description="List of minimum required service before archiving takes place")
    webhook = odm.Optional(odm.Compound(Webhook), description="Webhook to call before triggering the archiving process")
    use_metadata: bool = odm.Boolean(
        default=False, description="Should the UI ask form metadata to be filed out when archiving",
        deprecation="This field is no longer required...")
    use_webhook: bool = odm.Optional(odm.Boolean(
        default=False,
        description="Should the archiving go through the webhook prior to actually trigger the archiving function"))


DEFAULT_ARCHIVER = {
    'alternate_dtl': 0,
    'metadata': {},
    'minimum_required_services': [],
    'use_webhook': False,
    'use_metadata': False,
    'webhook': DEFAULT_ARCHIVER_WEBHOOK
}


@odm.model(index=False, store=False, description="Plumber Configuration")
class Plumber(odm.Model):
    notification_queue_interval: int = odm.Integer(
        description="Interval at which the notification queue cleanup should run")
    notification_queue_max_age: int = odm.Integer(
        description="Max age in seconds notification queue messages can be")


DEFAULT_PLUMBER = {
    'notification_queue_interval': 30 * 60,
    'notification_queue_max_age': 24 * 60 * 60
}


@odm.model(index=False, store=False, description="Redis Configuration")
class Redis(odm.Model):
    nonpersistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_NP,
                                              description="A volatile Redis instance")
    persistent: RedisServer = odm.Compound(RedisServer, default=DEFAULT_REDIS_P,
                                           description="A persistent Redis instance")


DEFAULT_REDIS = {
    "nonpersistent": DEFAULT_REDIS_NP,
    "persistent": DEFAULT_REDIS_P
}


@odm.model(index=False, store=False, description="A configuration for mounting existing volumes to a container")
class Mount(odm.Model):
    name: str = odm.Keyword(description="Name of volume mount")
    path: str = odm.Text(description="Target mount path")
    read_only: bool = odm.Boolean(default=True, description="Should this be mounted as read-only?")
    privileged_only: bool = odm.Boolean(default=False,
                                        description="Should this mount only be available for privileged services?")

    # Kubernetes-specific
    resource_type: str = odm.Enum(default='volume', values=['secret', 'configmap', 'volume'],
                                  description="Type of mountable Kubernetes resource")
    resource_name: str = odm.Optional(odm.Keyword(), description="Name of resource (Kubernetes only)")
    resource_key: str = odm.Optional(odm.Keyword(), description="Key of ConfigMap/Secret (Kubernetes only)")

    # TODO: Deprecate in next major change in favour of general configuration above for mounting Kubernetes resources
    config_map: str = odm.Optional(
        odm.Keyword(),
        description="Name of ConfigMap (Kubernetes only)",
        deprecation="Use `resource_type: configmap` and fill in the `resource_name` "
        "& `resource_key` fields to mount ConfigMaps")
    key: str = odm.Optional(
        odm.Keyword(),
        description="Key of ConfigMap (Kubernetes only)",
        deprecation="Use `resource_type: configmap` and fill in the `resource_name` "
        "& `resource_key` fields to mount ConfigMaps")


KUBERNETES_TOLERATION_OPS = ['Exists', 'Equal']
KUBERNETES_TOLERATION_EFFECTS = ['NoSchedule', 'PreferNoSchedule', 'NoExecute']


@odm.model(index=False, store=False, description="Limit a set of kubernetes objects based on a label query.")
class Toleration(odm.Model):
    key = odm.Optional(odm.Keyword(), description="The taint key that the toleration applies to")
    operator = odm.Enum(values=KUBERNETES_TOLERATION_OPS,
                        default="Equal", description="Relationship between taint key and value")
    value = odm.Optional(odm.Keyword(), description="Taint value the toleration matches to")
    effect = odm.Optional(odm.Enum(KUBERNETES_TOLERATION_EFFECTS), description="The taint effect to match.")
    toleration_seconds = odm.Optional(odm.Integer(min=0),
                                      description="The period of time the toleration tolerates the taint")


@odm.model(index=False, store=False,
           description="A set of default values to be used running a service when no other value is set")
class ScalerServiceDefaults(odm.Model):
    growth: int = odm.Integer(description="Period, in seconds, to wait before scaling up a service deployment")
    shrink: int = odm.Integer(description="Period, in seconds, to wait before scaling down a service deployment")
    backlog: int = odm.Integer(description="Backlog threshold that dictates scaling adjustments")
    min_instances: int = odm.Integer(description="The minimum number of service instances to be running")
    environment: List[EnvironmentVariable] = odm.List(odm.Compound(EnvironmentVariable), default=[],
                                                      description="Environment variables to pass onto services")
    mounts: List[Mount] = odm.List(odm.Compound(Mount), default=[],
                                   description="A list of volume mounts for every service")
    tolerations: List[Toleration] = odm.List(
        odm.Compound(Toleration),
        default=[],
        description="Toleration to apply to service pods.\n"
        "Reference: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/")


# The operations we support for label and field selectors are based on the common subset of
# what kubernetes supports on the list_node API endpoint and the nodeAffinity field
# on pod specifications. The selector needs to work in both cases because we use these
# selectors both for probing what nodes are available (list_node) and making sure
# the pods only run on the pods that are returned there (using nodeAffinity)

@odm.model(index=False, store=False, description="Limit a set of kubernetes objects based on a field query.")
class FieldSelector(odm.Model):
    key = odm.keyword(description="Name of a field to select on.")
    equal = odm.boolean(default=True, description="When true key must equal value, when false it must not")
    value = odm.keyword(description="Value to compare field to.")


# Excluded from this list is Gt and Lt for above reason
KUBERNETES_LABEL_OPS = ['In', 'NotIn', 'Exists', 'DoesNotExist']


@odm.model(index=False, store=False, description="Limit a set of kubernetes objects based on a label query.")
class LabelSelector(odm.Model):
    key = odm.keyword(description="Name of label to select on.")
    operator = odm.Enum(KUBERNETES_LABEL_OPS, description="Operation to select label with.")
    values = odm.sequence(odm.keyword(), description="Value list to compare label to.")


@odm.model(index=False, store=False)
class Selector(odm.Model):
    field = odm.sequence(odm.compound(FieldSelector), default=[],
                         description="Field selector for resource under kubernetes")
    label = odm.sequence(odm.compound(LabelSelector), default=[],
                         description="Label selector for resource under kubernetes")


@odm.model(index=False, store=False)
class Scaler(odm.Model):
    service_defaults: ScalerServiceDefaults = odm.Compound(ScalerServiceDefaults,
                                                           description="Defaults Scaler will assign to a service.")
    cpu_overallocation: float = odm.Float(description="Percentage of CPU overallocation")
    memory_overallocation: float = odm.Float(description="Percentage of RAM overallocation")
    overallocation_node_limit = odm.Optional(odm.Integer(description="If the system has this many nodes or "
                                                                     "more overallocation is ignored"))
    additional_labels: List[str] = odm.Optional(
        odm.List(odm.Text()), description="Additional labels to be applied to services('=' delimited)")
    privileged_services_additional_labels: List[str] = odm.Optional(
        odm.List(odm.Text()), description="Additional labels to be applied to privileged services only('=' delimited)")
    linux_node_selector = odm.compound(Selector, description="Selector for linux nodes under kubernetes")
    # windows_node_selector = odm.compound(Selector, description="Selector for windows nodes under kubernetes")
    cluster_pod_list = odm.boolean(default=True, description="Sets if scaler list pods for all namespaces. "
                                   "Disabling this lets you use stricter cluster roles but will make cluster resource "
                                   "usage less accurate, setting a namespace resource quota might be needed.")
    enable_pod_security = odm.boolean(
        default=False,
        description="Launch all containers in compliance with the 'Restricted' pod security standard.",
    )


DEFAULT_SCALER = {
    'additional_labels': None,
    'cpu_overallocation': 1,
    'memory_overallocation': 1,
    'overallocation_node_limit': None,
    'privileged_services_additional_labels': None,
    'service_defaults': {
        'growth': 60,
        'shrink': 30,
        'backlog': 100,
        'min_instances': 0,
        'environment': [
            {'name': 'SERVICE_API_HOST', 'value': 'http://service-server:5003'},
            {'name': 'AL_SERVICE_TASK_LIMIT', 'value': 'inf'},
        ],
    },
    'linux_node_selector': {
        'field': [],
        'label': [],
    },
    # 'windows_node_selector': {
    #     'field': [],
    #     'label': [],
    # },
}


@odm.model(index=False, store=False)
class RegistryConfiguration(odm.Model):
    name: str = odm.Text(description="Name of container registry")
    proxies: Dict = odm.Optional(odm.Mapping(odm.Text()),
                                 description="Proxy configuration that is passed to Python Requests")
    token_server: str = odm.Optional(odm.Text(),
                                     description="Token server name to facilitate anonymous pull access")


@odm.model(index=False, store=False)
class Updater(odm.Model):
    job_dockerconfig: DockerConfigDelta = odm.Compound(
        DockerConfigDelta, description="Container configuration used for service registration/updates")
    registry_configs: List = odm.List(odm.Compound(RegistryConfiguration),
                                      description="Configurations to be used with container registries")


DEFAULT_UPDATER = {
    'job_dockerconfig': {
        'cpu_cores': 1,
        'ram_mb': 1024,
        'ram_mb_min': 256,
    },
    'registry_configs': [{
        'name': 'registry.hub.docker.com',
        'proxies': {}
    }]
}


@odm.model(index=False, store=False)
class VacuumSafelistItem(odm.Model):
    name = odm.Keyword()
    conditions = odm.Mapping(odm.Keyword())


@odm.model(index=False, store=False)
class Vacuum(odm.Model):
    list_cache_directory: str = odm.Keyword()
    worker_cache_directory: str = odm.Keyword()
    data_directories: List[str] = odm.List(odm.Keyword())
    file_directories: List[str] = odm.List(odm.Keyword())
    assemblyline_user: str = odm.Keyword()
    department_map_url = odm.Optional(odm.Keyword())
    department_map_init = odm.Optional(odm.Keyword())
    stream_map_url = odm.Optional(odm.Keyword())
    stream_map_init = odm.Optional(odm.Keyword())
    safelist = odm.List(odm.Compound(VacuumSafelistItem))
    worker_threads: int = odm.Integer()
    worker_rollover: int = odm.Integer()
    minimum_classification: str = odm.Keyword()
    ingest_type = odm.keyword()


DEFAULT_VACUUM = dict(
    list_cache_directory="/cache/",
    worker_cache_directory="/memory/",
    data_directories=[],
    file_directories=[],
    assemblyline_user="vacuum-service-account",
    department_map_url=None,
    department_map_init=None,
    stream_map_url=None,
    stream_map_init=None,
    safelist=[],
    worker_threads=50,
    worker_rollover=1000,
    minimum_classification='U',
    ingest_type='VACUUM',
)


@odm.model(index=False, store=False, description="Core Component Configuration")
class Core(odm.Model):
    alerter: Alerter = odm.Compound(Alerter, default=DEFAULT_ALERTER, description="Configuration for Alerter")
    archiver: Archiver = odm.Compound(Archiver, default=DEFAULT_ARCHIVER,
                                      description="Configuration for the permanent submission archive")
    dispatcher: Dispatcher = odm.Compound(Dispatcher, default=DEFAULT_DISPATCHER,
                                          description="Configuration for Dispatcher")
    expiry: Expiry = odm.Compound(Expiry, default=DEFAULT_EXPIRY, description="Configuration for Expiry")
    ingester: Ingester = odm.Compound(Ingester, default=DEFAULT_INGESTER, description="Configuration for Ingester")
    metrics: Metrics = odm.Compound(Metrics, default=DEFAULT_METRICS,
                                    description="Configuration for Metrics Collection")
    plumber: Plumber = odm.Compound(Plumber, default=DEFAULT_PLUMBER,
                                    description="Configuration for system cleanup")
    redis: Redis = odm.Compound(Redis, default=DEFAULT_REDIS, description="Configuration for Redis instances")
    scaler: Scaler = odm.Compound(Scaler, default=DEFAULT_SCALER, description="Configuration for Scaler")
    updater: Updater = odm.Compound(Updater, default=DEFAULT_UPDATER, description="Configuration for Updater")
    vacuum: Vacuum = odm.Compound(Vacuum, default=DEFAULT_VACUUM, description="Configuration for Vacuum")


DEFAULT_CORE = {
    "alerter": DEFAULT_ALERTER,
    "archiver": DEFAULT_ARCHIVER,
    "dispatcher": DEFAULT_DISPATCHER,
    "expiry": DEFAULT_EXPIRY,
    "ingester": DEFAULT_INGESTER,
    "metrics": DEFAULT_METRICS,
    "plumber": DEFAULT_PLUMBER,
    "redis": DEFAULT_REDIS,
    "scaler": DEFAULT_SCALER,
    "updater": DEFAULT_UPDATER,
}


@odm.model(index=False, store=False, description="Datastore Archive feature configuration")
class Archive(odm.Model):
    enabled = odm.Boolean(description="Are we enabling Achiving features across indices?")
    indices = odm.List(odm.Keyword(), description="List of indices the ILM Applies to")


DEFAULT_ARCHIVE = {
    "enabled": False,
    "indices": ['file', 'submission', 'result'],
}


@odm.model(index=False, store=False, description="Datastore Configuration")
class Datastore(odm.Model):
    hosts: List[str] = odm.List(odm.Keyword(), description="List of hosts used for the datastore")
    archive = odm.Compound(Archive, default=DEFAULT_ARCHIVE, description="Datastore Archive feature configuration")
    cache_dtl = odm.Integer(
        min=0,
        default=5, description="Default cache lenght for computed indices (submission_tree, submission_summary...")
    type = odm.Enum({"elasticsearch"}, description="Type of application used for the datastore")


DEFAULT_DATASTORE = {
    "hosts": ["http://elastic:devpass@localhost:9200"],
    "archive": DEFAULT_ARCHIVE,
    "cache_dtl": 5,
    "type": "elasticsearch",
}


@odm.model(index=False, store=False, description="Datasource Configuration")
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


@odm.model(index=False, store=False, description="Filestore Configuration")
class Filestore(odm.Model):
    archive: List[str] = odm.List(odm.Keyword(), description="List of filestores used for malware archive")
    cache: List[str] = odm.List(odm.Keyword(), description="List of filestores used for caching")
    storage: List[str] = odm.List(odm.Keyword(), description="List of filestores used for storage")


DEFAULT_FILESTORE = {
    "archive": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-archive&use_ssl=False"],
    "cache": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-cache&use_ssl=False"],
    "storage": ["s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000?s3_bucket=al-storage&use_ssl=False"]
}


@odm.model(index=False, store=False, description="Model Definition for the Logging Configuration")
class Logging(odm.Model):
    log_level: str = odm.Enum(values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "DISABLED"],
                              description="What level of logging should we have?")
    log_to_console: bool = odm.Boolean(description="Should we log to console?")
    log_to_file: bool = odm.Boolean(description="Should we log to files on the server?")
    log_directory: str = odm.Keyword(description="If `log_to_file: true`, what is the directory to store logs?")
    log_to_syslog: bool = odm.Boolean(description="Should logs be sent to a syslog server?")
    syslog_host: str = odm.Keyword(description="If `log_to_syslog: true`, provide hostname/IP of the syslog server?")
    syslog_port: int = odm.Integer(description="If `log_to_syslog: true`, provide port of the syslog server?")
    export_interval: int = odm.Integer(description="How often, in seconds, should counters log their values?")
    log_as_json: bool = odm.Boolean(description="Log in JSON format?")
    heartbeat_file: str = odm.Optional(
        odm.Keyword(),
        description="Add a health check to core components.<br>"
        "If `true`, core components will touch this path regularly to tell the container environment it is healthy")


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
    'Internet Connected',
    'Networking',
    'Static Analysis',
]

SERVICE_STAGES = [
    'FILTER',
    'EXTRACT',
    'CORE',
    'SECONDARY',
    'POST',
    'REVIEW'
]

SAFELIST_HASH_TYPES = ['sha1', 'sha256', 'md5']
REGISTRY_TYPES = ['docker', 'harbor']


@odm.model(index=False, store=False, description="Service's Safelisting Configuration")
class ServiceSafelist(odm.Model):
    enabled = odm.Boolean(default=True,
                          description="Should services be allowed to check extracted files against safelist?")
    hash_types = odm.List(odm.Enum(values=SAFELIST_HASH_TYPES),
                          default=['sha1', 'sha256'],
                          description="Types of file hashes used for safelist checks")
    enforce_safelist_service = odm.Boolean(default=False,
                                           description="Should the Safelist service always run on extracted files?")


@odm.model(index=False, store=False, description="Pre-Configured Registry Details for Services")
class ServiceRegistry(odm.Model):
    name: str = odm.Keyword(description="Name of container registry")
    type: str = odm.Enum(values=REGISTRY_TYPES, default='docker', description="Type of container registry")
    username: str = odm.Optional(odm.Keyword(description="Username for container registry"))
    password: str = odm.Optional(odm.Keyword(description="Password for container registry"))
    use_fic: bool = odm.Boolean(
        default=False,
        description="Use federated identity credential token instead of user/passwords combinaison (ACR Only)")


@odm.model(index=False, store=False, description="Services Configuration")
class Services(odm.Model):
    categories: List[str] = odm.List(odm.Keyword(), description="List of categories a service can be assigned to")
    default_auto_update: bool = odm.Boolean(default=False, description="Should services be auto-updated?")
    default_timeout: int = odm.Integer(description="Default service timeout time in seconds")
    stages: List[str] = odm.List(odm.Keyword(), description="List of execution stages a service can be assigned to")
    image_variables: Dict[str, str] = odm.Mapping(odm.Keyword(default=''),
                                                  description="Substitution variables for image paths "
                                                  "(for custom registry support)")
    update_image_variables: Dict[str, str] = odm.Mapping(
        odm.Keyword(default=''), description="Similar to `image_variables` but only applied to the updater. "
                                             "Intended for use with local registries.")
    preferred_update_channel: str = odm.Keyword(description="Default update channel to be used for new services")
    allow_insecure_registry: bool = odm.Boolean(description="Allow fetching container images from insecure registries")

    preferred_registry_type: str = odm.Enum(
        values=REGISTRY_TYPES,
        default='docker',
        description="Global registry type to be used for fetching updates for a service (overridable by a service)")
    prefer_service_privileged: bool = odm.Boolean(
        default=False,
        description="Global preference that controls if services should be "
                    "privileged to communicate with core infrastucture")
    cpu_reservation: float = odm.Float(
        description="How much CPU do we want to reserve relative to the service's request?<br>"
        "At `1`, a service's full CPU request will be reserved for them.<br>"
        "At `0` (only for very small appliances/dev boxes), the service's CPU will be limited "
        "but no CPU will be reserved allowing for more flexible scheduling of containers.")
    safelist = odm.Compound(ServiceSafelist)
    registries = odm.Optional(odm.List(odm.Compound(ServiceRegistry)),
                              description="Global set of registries for services")
    service_account = odm.optional(odm.keyword(),
                                   description="Service account to use for pods in kubernete"
                                   "where the service does not have one configured.",
                                   deprecation="Use helm values to specify service accounts settings for "
                                   "(non-)privileged services: "
                                   "`privilegedServiceAccountName`, `unprivilegedServiceAccountName`")


DEFAULT_SERVICES = {
    "categories": SERVICE_CATEGORIES,
    "default_auto_update": False,
    "default_timeout": 60,
    "stages": SERVICE_STAGES,
    "image_variables": {},
    "update_image_variables": {},
    "preferred_update_channel": "stable",
    "allow_insecure_registry": False,
    "cpu_reservation": 0.25,
    "safelist": {
        "enabled": True,
        "hash_types": ['sha1', 'sha256'],
        "enforce_safelist_service": False
    },
    "registries": []
}


@odm.model(index=False, store=False, description="System Configuration")
class System(odm.Model):
    constants: str = odm.Keyword(description="Module path to the assemblyline constants")
    organisation: str = odm.Text(description="Organisation acronym used for signatures")
    type: str = odm.Enum(values=['production', 'staging', 'development'], description="Type of system")


DEFAULT_SYSTEM = {
    "constants": "assemblyline.common.constants",
    "organisation": "ACME",
    "type": 'production',
}


@odm.model(index=False, store=False, description="Statistics")
class Statistics(odm.Model):
    alert: List[str] = odm.List(odm.Keyword(),
                                description="Fields used to generate statistics in the Alerts page")
    submission: List[str] = odm.List(odm.Keyword(),
                                     description="Fields used to generate statistics in the Submissions page")


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


@odm.model(index=False, store=False, description="Parameters used during a AI query")
class AIQueryParams(odm.Model):
    system_message: str = odm.Keyword(
        description="System message used for the query.")
    task: str = odm.Keyword(default="", description="Task description sent to the AI")
    max_tokens: int = odm.Integer(description="Maximum ammount of token used for the response.")
    options: Dict[str, str] = odm.Optional(odm.Mapping(odm.Any()),
                                           description="Other kwargs options directly passed to the API.")


@odm.model(index=False, store=False, description="AI support configuration block")
class AI(odm.Model):
    chat_url: str = odm.Keyword(description="URL to the AI API")
    api_type: str = odm.Enum(values=['openai', 'cohere'], description="Type of chat API we are communicating with")
    assistant: AIQueryParams = odm.Compound(AIQueryParams, description="Parameters used for Assamblyline Assistant")
    code: AIQueryParams = odm.Compound(AIQueryParams, description="Parameters used for code analysis")
    detailed_report: AIQueryParams = odm.Compound(AIQueryParams, description="Parameters used for detailed reports")
    executive_summary: AIQueryParams = odm.Compound(
        AIQueryParams, description="Parameters used for executive summaries")
    enabled: bool = odm.Boolean(description="Is AI support enabled?")
    headers: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()),
                                           description="Headers used by the _call_ai_backend method")
    model_name: str = odm.Keyword(description="Name of the model to be used for the AI analysis.")
    verify: bool = odm.Boolean(description="Should the SSL connection to the AI API be verified.")
    proxies: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()),
                                           description="Proxies used by the _call_ai_backend method")


DEFAULT_AI_ASSISTANT = {
    'system_message': """## Context

You are the Assemblyline (AL) AI Assistant. You help people answer their questions and other requests interactively
regarding Assemblyline. $(EXTRA_CONTEXT)

## Style Guide

- Your output must be formatted in standard Markdown syntax
- Highlight important information using backticks
- Your answer must be written in plain $(LANG).
""",
    'max_tokens': 1024,
    'options': {
        "frequency_penalty": 0,
        "presence_penalty": 0,
        "temperature": 0,
        "top_p": 0
    }
}


DEFAULT_AI_CODE = {
    'system_message': """## Context

You are an assistant that provides explanation of code snippets found in AssemblyLine (AL),
a malware detection and analysis tool. $(EXTRA_CONTEXT)

## Style Guide

- Your output must be formatted in standard Markdown syntax
- Highlight important information using backticks
- Your answer must be written in plain $(LANG).
""",
    'task': """Take the code file below and give me a two part result:

- The first part is a short summary of the intent behind the code titled "## Summary"
- The second part is a detailed explanation of what the code is doing titled "## Detailed Analysis"
""",
    'max_tokens': 1024,
    'options': {
        "frequency_penalty": 0,
        "presence_penalty": 0,
        "temperature": 0,
        "top_p": 0
    }
}


DEFAULT_AI_DETAILED_REPORT = {
    'system_message': """## Context

You are an assistant that summarizes the output of AssemblyLine (AL), a malware detection and analysis tool.
Your role is to extract information of importance and discard what is not. $(EXTRA_CONTEXT)

## Style Guide

- Your output must be formatted in standard Markdown syntax
- Highlight important information using backticks
- Your answer must be written in plain $(LANG).
""",
    'task': """Take the Assemblyline report below in yaml format and create a two part result:

- The first part is a one or two paragraph executive summary titled "## Executive Summary" which
  provides some high level highlights of the results
- The second part is a detailed description of the observations found in the report, this section
  is titled "## Detailed Analysis"
""",
    'max_tokens': 2048,
    'options': {
        "frequency_penalty": 0,
        "presence_penalty": 0,
        "temperature": 0,
        "top_p": 0
    }
}


DEFAULT_AI_EXECUTIVE_SUMMARY = {
    "system_message": """## Context

You are an assistant that summarizes the output of AssemblyLine (AL), a malware detection and analysis tool. Your role
is to extract information of importance and discard what is not. $(EXTRA_CONTEXT)

## Style Guide

- Your output must be formatted in standard Markdown syntax
- Highlight important information using backticks
- Your answer must be written in plain $(LANG).
""",
    'task': """Take the Assemblyline report below in yaml format and summarize the information found in the
report into a one or two paragraph executive summary. DO NOT write any headers in your output.
""",
    'max_tokens': 1024,
    'options': {
        "frequency_penalty": 0,
        "presence_penalty": 0,
        "temperature": 0,
        "top_p": 0
    }
}


DEFAULT_AI = {
    'chat_url': "https://api.openai.com/v1/chat/completions",
    'api_type': "openai",
    'assistant': DEFAULT_AI_ASSISTANT,
    'code': DEFAULT_AI_CODE,
    'detailed_report': DEFAULT_AI_DETAILED_REPORT,
    'executive_summary': DEFAULT_AI_EXECUTIVE_SUMMARY,
    'enabled': False,
    'headers': {
        "Content-Type": "application/json"
    },
    'model_name': "gpt-3.5-turbo",
    'verify': True
}


@odm.model(index=False, store=False, description="Connection information to an AI backend")
class AIConnection(odm.Model):
    api_type: str = odm.Enum(values=['openai', 'cohere'], description="Type of chat API we are communicating with")
    chat_url: str = odm.Keyword(description="URL to the AI API")
    headers: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()), default={},
                                           description="Headers used by the _call_ai_backend method")
    model_name: str = odm.Keyword(description="Name of the model to be used for the AI analysis.")
    proxies: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()),
                                           description="Proxies used by the _call_ai_backend method")
    use_fic: bool = odm.Boolean(default=False, description="Use Federated Identity Credentials to login")
    verify: bool = odm.Boolean(default=True, description="Should the SSL connection to the AI API be verified.")


@odm.model(index=False, store=False, description="Definition of each parameters used in the different AI functions")
class AIFunctionParameters(odm.Model):
    assistant: AIQueryParams = odm.Compound(AIQueryParams, description="Parameters used for Assamblyline Assistant")
    code: AIQueryParams = odm.Compound(AIQueryParams, description="Parameters used for code analysis")
    detailed_report: AIQueryParams = odm.Compound(AIQueryParams, description="Parameters used for detailed reports")
    executive_summary: AIQueryParams = odm.Compound(
        AIQueryParams, description="Parameters used for executive summaries")


@odm.model(index=False, store=False, description="AI Multi-Backend support configuration block")
class AIBackends(odm.Model):
    enabled: bool = odm.Boolean(description="Is AI support enabled?")
    api_connections: List[Dict] = odm.List(odm.Compound(AIConnection),
                                           description="List of API definitions use in the API Pool")
    function_params: AIFunctionParameters = odm.Compound(
        AIFunctionParameters, description="Definition of each parameters used in the different AI functions")


DEFAULT_MAIN_CONNECTION = {
    'chat_url': "https://api.openai.com/v1/chat/completions",
    'api_type': "openai",
    'headers': {
        "Content-Type": "application/json"
    },
    'model_name': "gpt-3.5-turbo",
    'proxies': None,
    'verify': True
}


DEFAULT_FALLBACK_CONNECTION = {
    'chat_url': "https://api.openai.com/v1/chat/completions",
    'api_type': "openai",
    'headers': {
        "Content-Type": "application/json"
    },
    'model_name': "gpt-4",
    'proxies': None,
    'verify': True
}

DEFAULT_AI_BACKENDS = {
    'enabled': False,
    'api_connections': [DEFAULT_MAIN_CONNECTION, DEFAULT_FALLBACK_CONNECTION],
    'function_params': {
        'assistant': DEFAULT_AI_ASSISTANT,
        'code': DEFAULT_AI_CODE,
        'detailed_report': DEFAULT_AI_DETAILED_REPORT,
        'executive_summary': DEFAULT_AI_EXECUTIVE_SUMMARY,
    }
}


@odm.model(index=False, store=False, description="Alerting Metadata")
class AlertingMeta(odm.Model):
    important: List[str] = odm.List(odm.Keyword(), description="Metadata keys that are considered important")
    subject: List[str] = odm.List(odm.Keyword(), description="Metadata keys that refer to an email's subject")
    url: List[str] = odm.List(odm.Keyword(), description="Metadata keys that refer to a URL")


DEFAULT_ALERTING_META = {
    'important': [
        'original_source',
        'protocol',
        'subject',
        'submitted_url',
        'source_url',
        'url',
        'web_url',
        'from',
        'to',
        'cc',
        'bcc',
        'ip_src',
        'ip_dst',
        'source'
    ],
    'subject': [
        'subject'
    ],
    'url': [
        'submitted_url',
        'source_url',
        'url',
        'web_url'
    ]

}


@odm.model(index=False, store=False, description="Target definition of an external link")
class ExternalLinksTargets(odm.Model):
    type: str = odm.Enum(values=['metadata', 'tag', 'hash'], description="Type of external link target")
    key: str = odm.Keyword(description="Key that it can be used against")


@odm.model(index=False, store=False, description="External links that specific metadata and tags can pivot to")
class ExternalLinks(odm.Model):
    allow_bypass: bool = odm.boolean(
        default=False,
        description="If the classification of the item is higher than the max_classificaiton, can we let the user "
                    "bypass the check and still query the external link?")
    name: str = odm.Keyword(description="Name of the link")
    double_encode: bool = odm.boolean(default=False, description="Should the replaced value be double encoded?")
    classification = odm.Optional(
        odm.ClassificationString(description="Minimum classification the user must have to see this link"))
    max_classification = odm.Optional(
        odm.ClassificationString(description="Maximum classification of data that may be handled by the link"))
    replace_pattern: str = odm.Keyword(
        description="Pattern that will be replaced in the URL with the metadata or tag value")
    targets: List[ExternalLinksTargets] = odm.List(
        odm.Compound(ExternalLinksTargets),
        default=[],
        description="List of external sources to query")
    url: str = odm.Keyword(description="URL to redirect to")


EXAMPLE_EXTERNAL_LINK_VT = {
    # This is an example on how this would work with VirusTotal
    "name": "VirusTotal",
    "replace_pattern": "{REPLACE}",
    "targets": [
        {"type": "tag", "key": "network.static.uri"},
        {"type": "tag", "key": "network.dynamic.uri"},
        {"type": "metadata", "key": "submitted_url"},
        {"type": "hash", "key": "md5"},
        {"type": "hash", "key": "sha1"},
        {"type": "hash", "key": "sha256"},
    ],
    "url": "https://www.virustotal.com/gui/search/{REPLACE}",
    "double_encode": True,
    # "classification": "TLP:CLEAR",
    # "max_classification": "TLP:CLEAR",
}

EXAMPLE_EXTERNAL_LINK_MB_SHA256 = {
    # This is an example on how this would work with Malware Bazaar
    "name": "MalwareBazaar",
    "replace_pattern": "{REPLACE}",
    "targets": [
        {"type": "hash", "key": "sha256"},
    ],
    "url": "https://bazaar.abuse.ch/sample/{REPLACE}/",
    # "classification": "TLP:CLEAR",
    # "max_classification": "TLP:CLEAR",
}


@odm.model(index=False, store=False, description="Connection details for external systems/data sources.")
class ExternalSource(odm.Model):
    name: str = odm.Keyword(description="Name of the source.")
    classification = odm.Optional(
        odm.ClassificationString(
            description="Minimum classification applied to information from the source"
                        " and required to know the existance of the source."))
    max_classification = odm.Optional(
        odm.ClassificationString(description="Maximum classification of data that may be handled by the source"))
    url: str = odm.Keyword(description="URL of the upstream source's lookup service.")


EXAMPLE_EXTERNAL_SOURCE_VT = {
    # This is an example on how this would work with VirusTotal
    "name": "VirusTotal",
    "url": "vt-lookup.namespace.svc.cluster.local",
    "classification": "TLP:CLEAR",
    "max_classification": "TLP:CLEAR",
}

EXAMPLE_EXTERNAL_SOURCE_MB = {
    # This is an example on how this would work with Malware Bazaar
    "name": "Malware Bazaar",
    "url": "mb-lookup.namespace.scv.cluster.local",
    "classification": "TLP:CLEAR",
    "max_classification": "TLP:CLEAR",
}


@odm.model(index=False, store=False, description="Default API and submission quota values for the system")
class Quotas(odm.Model):
    concurrent_api_calls: int = odm.Integer(description="Maximum concurrent API Calls that can be running for a user.")
    concurrent_submissions: int = odm.Integer(
        description="Maximum concurrent Submission that can be running for a user.")
    concurrent_async_submissions: int = odm.Integer(
        description="Maximum concurrent asynchroneous Submission that can be running for a user.")
    daily_api_calls: int = odm.Integer(description="Maximum daily API calls a user can issue.")
    daily_submissions: int = odm.Integer(description="Maximum daily submission a user can do.")


DEFAULT_QUOTAS = {
    'concurrent_api_calls': DEFAULT_API_QUOTA,
    'concurrent_submissions': DEFAULT_SUBMISSION_QUOTA,
    'concurrent_async_submissions': DEFAULT_ASYNC_SUBMISSION_QUOTA,
    'daily_api_calls': DEFAULT_DAILY_API_QUOTA,
    'daily_submissions': DEFAULT_DAILY_SUBMISSION_QUOTA
}


@odm.model(index=False, store=False, description="Header value")
class HeaderValue(odm.Model):
    name = odm.Keyword(description="Name of the header")
    value = odm.Optional(odm.Keyword(description="Explicit value to put in the header"))
    key = odm.Optional(odm.Keyword(description="Key to lookup in the currently logged in user"))


@odm.model(index=False, store=False, description="Configuration for connecting to a retrohunt service.")
class APIProxies(odm.Model):
    url = odm.Keyword(description="URL to redirect to")
    verify = odm.Boolean(default=True, description="Should we verify the cert or not")
    headers = odm.List(odm.Compound(HeaderValue), default=[], description="Headers to add to the request")
    public: Dict[str, str] = odm.Optional(odm.Mapping(odm.Any()), description="Parameters to be sent to the Frontend.")


DEFAULT_API_PROXIES = {}
DOWNLOAD_ENCODINGS = ["cart", "raw", "zip"]


@odm.model(index=False, store=False, description="UI Configuration")
class UI(odm.Model):
    ai: AI = odm.Compound(AI, default=DEFAULT_AI, description="AI support for the UI")
    ai_backends: AIBackends = odm.Compound(AIBackends, default=DEFAULT_AI_BACKENDS,
                                           description="AI Multi-backends support for the UI")
    alerting_meta: AlertingMeta = odm.Compound(AlertingMeta, default=DEFAULT_ALERTING_META,
                                               description="Alerting metadata fields")
    allow_malicious_hinting: bool = odm.Boolean(
        description="Allow user to tell in advance the system that a file is malicious?")
    allow_raw_downloads: bool = odm.Boolean(description="Allow user to download raw files?")
    allow_zip_downloads: bool = odm.Boolean(description="Allow user to download files as password protected ZIPs?")
    allow_replay: bool = odm.Boolean(description="Allow users to request replay on another server?")
    allow_url_submissions: bool = odm.Boolean(description="Allow file submissions via url?")
    api_proxies: APIProxies = odm.Mapping(
        odm.Compound(APIProxies),
        default=DEFAULT_API_PROXIES, description="Proxy requests to the configured API target and add headers")
    audit: bool = odm.Boolean(description="Should API calls be audited and saved to a separate log file?")
    audit_login: bool = odm.Boolean(description="Should login successes and failures be part of the audit log as well?")
    banner: Dict[str, str] = odm.Optional(odm.Mapping(
        odm.Keyword()), description="Banner message display on the main page (format: {<language_code>: message})")
    banner_level: str = odm.Enum(
        values=["info", "warning", "success", "error"],
        description="Banner message level")
    debug: bool = odm.Boolean(description="Enable debugging?")
    default_quotas: Quotas = odm.Compound(Quotas, default=DEFAULT_QUOTAS,
                                          description="Default API quotas values")
    discover_url: str = odm.Optional(odm.Keyword(), description="Discover URL")
    download_encoding = odm.Enum(values=DOWNLOAD_ENCODINGS, description="Which encoding will be used for downloads?")
    default_zip_password = odm.Optional(
        odm.Text(), description="Default user-defined password for creating password protected ZIPs when downloading files")
    email: str = odm.Optional(odm.Email(), description="Assemblyline admins email address")
    enforce_quota: bool = odm.Boolean(description="Enforce the user's quotas?")
    external_links: List[ExternalLinks] = odm.List(
        odm.Compound(ExternalLinks),
        description="List of external pivot links")
    external_sources: List[ExternalSource] = odm.List(
        odm.Compound(ExternalSource), description="List of external sources to query")
    fqdn: str = odm.Text(description="Fully qualified domain name to use for the 2-factor authentication validation")
    ingest_max_priority: int = odm.Integer(description="Maximum priority for ingest API", max=PRIORITIES['critical'])
    read_only: bool = odm.Boolean(description="Turn on read only mode in the UI")
    read_only_offset: str = odm.Keyword(
        default="", description="Offset of the read only mode for all paging and searches")
    rss_feeds: List[str] = odm.List(odm.Keyword(), default=[], description="List of RSS feeds to display on the UI")
    services_feed: str = odm.Keyword(description="Feed of all the services built by the Assemblyline Team")
    community_feed: str = odm.Keyword(description="Feed of all the services built by the Assemblyline community.")
    secret_key: str = odm.Keyword(description="Flask secret key to store cookies, etc.")
    session_duration: int = odm.Integer(description="Duration of the user session before the user has to login again")
    statistics: Statistics = odm.Compound(Statistics, default=DEFAULT_STATISTICS,
                                          description="Statistics configuration")
    tos: str = odm.Optional(odm.Text(), description="Terms of service")
    tos_lockout: bool = odm.Boolean(description="Lock out user after accepting the terms of service?")
    tos_lockout_notify: List[str] = odm.Optional(odm.List(odm.Keyword()),
                                                 description="List of admins to notify when a user gets locked out")
    url_submission_auto_service_selection: List[str] = odm.List(
        odm.Keyword(), description="List of services auto-selected by the UI when submitting URLs")
    url_submission_headers: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()),
                                                          description="Headers used by the url_download method")
    url_submission_proxies: Dict[str, str] = odm.Optional(odm.Mapping(odm.Keyword()),
                                                          description="Proxy used by the url_download method")
    url_submission_timeout: int = odm.Integer(default=15, description="Request timeout for fetching URLs")
    validate_session_ip: bool = \
        odm.Boolean(description="Validate if the session IP matches the IP the session was created from")
    validate_session_useragent: bool = \
        odm.Boolean(description="Validate if the session useragent matches the useragent the session was created with")


DEFAULT_UI = {
    "ai": DEFAULT_AI,
    "ai_backends": DEFAULT_AI_BACKENDS,
    "alerting_meta": DEFAULT_ALERTING_META,
    "allow_malicious_hinting": False,
    "allow_raw_downloads": True,
    "allow_zip_downloads": True,
    "allow_replay": False,
    "allow_url_submissions": True,
    "api_proxies": DEFAULT_API_PROXIES,
    "audit": True,
    "audit_login": False,
    "banner": None,
    "banner_level": 'info',
    "debug": False,
    "default_quotas": DEFAULT_QUOTAS,
    "discover_url": None,
    "download_encoding": "cart",
    "default_zip_password": "infected",
    "email": None,
    "enforce_quota": True,
    "external_links": [],
    "external_sources": [],
    "fqdn": "localhost",
    "ingest_max_priority": 250,
    "read_only": False,
    "read_only_offset": "",
    "rss_feeds": [
        "https://alpytest.blob.core.windows.net/pytest/stable.json",
        "https://alpytest.blob.core.windows.net/pytest/services.json",
        "https://alpytest.blob.core.windows.net/pytest/community.json",
        "https://alpytest.blob.core.windows.net/pytest/blog.json"
    ],
    "services_feed": "https://alpytest.blob.core.windows.net/pytest/services.json",
    "community_feed": "https://alpytest.blob.core.windows.net/pytest/community.json",
    "secret_key": "This is the default flask secret key... you should change this!",
    "session_duration": 3600,
    "statistics": DEFAULT_STATISTICS,
    "tos": None,
    "tos_lockout": False,
    "tos_lockout_notify": None,
    "url_submission_auto_service_selection": ["URLDownloader"],
    "url_submission_headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko)"
                      " Chrome/110.0.0.0 Safari/537.36"
    },
    "url_submission_proxies": {},
    "validate_session_ip": True,
    "validate_session_useragent": True,
}


# Options regarding all submissions, regardless of their input method
@odm.model(index=False, store=False)
class TagTypes(odm.Model):
    attribution: List[str] = odm.List(odm.Keyword(), description="Attibution tags")
    behavior: List[str] = odm.List(odm.Keyword(), description="Behaviour tags")
    ioc: List[str] = odm.List(odm.Keyword(), description="IOC tags")


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


@odm.model(index=False, store=False, description="A source entry for the sha256 downloader")
class Sha256Source(odm.Model):
    name: str = odm.Keyword(description="Name of the sha256 source")
    classification = odm.Optional(
        odm.ClassificationString(
            description="Minimum classification applied to the downloaded "
                        "files and required to know the existance of the source."))
    data: str = odm.Optional(odm.Keyword(description="Data block sent during the URL call (Uses replace pattern)"))
    failure_pattern: str = odm.Optional(odm.Keyword(
        description="Pattern to find as a failure case when API return 200 OK on failures..."))
    method: str = odm.Enum(values=['GET', 'POST'], default="GET", description="Method used to call the URL")
    url: str = odm.Keyword(description="Url to fetch the file via SHA256 from (Uses replace pattern)")
    replace_pattern: str = odm.Keyword(description="Pattern to replace in the URL with the SHA256")
    headers: Dict[str, str] = odm.Mapping(odm.Keyword(), default={},
                                          description="Headers used to connect to the URL")
    proxies: Dict[str, str] = odm.Mapping(odm.Keyword(), default={},
                                          description="Proxy used to connect to the URL")
    verify: bool = odm.Boolean(default=True, description="Should the download function Verify SSL connections?")


HASH_PATTERN_MAP = {
    "sha256": odm.SHA256_REGEX,
    "sha1": odm.SHA1_REGEX,
    "md5": odm.MD5_REGEX,
    "tlsh": odm.TLSH_REGEX,
    "ssdeep": odm.SSDEEP_REGEX,
}


@odm.model(index=False, store=False, description="A file source entry for remote fetching via string")
class FileSource(odm.Model):
    name: str = odm.Keyword(description="Name of the sha256 source")
    auto_select: bool = odm.boolean(
        default=False, description="Should we force the source to be auto-selected for the user ?")
    download_from_url: bool = odm.boolean(
        default=True,
        description="Should we download from the resulting URL or create an Assemblyline URI file for it ?")
    hash_types: List[str] = odm.List(odm.Keyword(), default=["sha256"],
                                     description="Method(s) of fetching file from source by string input"
                                     f"(ie. {list(HASH_PATTERN_MAP.keys())}). This also supports custom types."
                                     )
    hash_patterns: Dict[str, str] = odm.Optional(odm.Mapping(
        odm.Text()), description="Custom types to regex pattern definition for input detection/validation")
    classification = odm.Optional(
        odm.ClassificationString(
            description="Minimum classification applied to the downloaded "
                        "files and required to know the existance of the source."))
    data: str = odm.Optional(odm.Keyword(description="Data block sent during the URL call (Uses replace pattern)"))
    failure_pattern: str = odm.Optional(odm.Keyword(
        description="Pattern to find as a failure case when API return 200 OK on failures..."))
    method: str = odm.Enum(values=['GET', 'POST'], default="GET", description="Method used to call the URL")
    url: str = odm.Keyword(description="Url to fetch the file via SHA256 from (Uses replace pattern)")
    replace_pattern: str = odm.Keyword(description="Pattern to replace in the URL with the SHA256")
    headers: Dict[str, str] = odm.Mapping(odm.Keyword(), default={},
                                          description="Headers used to connect to the URL")
    proxies: Dict[str, str] = odm.Mapping(odm.Keyword(), default={},
                                          description="Proxy used to connect to the URL")
    select_services: bool = odm.List(odm.keyword(),
                                     default=[], description="List of services that will be auto-selected when using this source.")
    verify: bool = odm.Boolean(default=True, description="Should the download function Verify SSL connections?")


EXAMPLE_FILE_SOURCE_VT = {
    # This is an example on how this would work with VirusTotal as a file source
    # Note: This supports downloading using multiple hash types in a single source configuration
    "name": "VirusTotal",
    "hash_types": ["sha256", "sha1", "md5"],
    "url": r"https://www.virustotal.com/api/v3/files/{HASH}/download",
    "replace_pattern": r"{HASH}",
    "headers": {"x-apikey": "YOUR_KEY"},
}

EXAMPLE_SHA256_SOURCE_VT = {
    # This is an example on how this would work with VirusTotal
    "name": "VirusTotal",
    "url": r"https://www.virustotal.com/api/v3/files/{SHA256}/download",
    "replace_pattern": r"{SHA256}",
    "headers": {"x-apikey": "YOUR_KEY"},
}

EXAMPLE_SHA256_SOURCE_MB = {
    # This is an example on how this would work with Malware Bazaar
    "name": "Malware Bazaar",
    "url": r"https://mb-api.abuse.ch/api/v1/",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "data": r"query=get_file&sha256_hash={SHA256}",
    "method": "POST",
    "replace_pattern": r"{SHA256}",
    "failure_pattern": '"query_status": "file_not_found"'
}

EXAMPLE_SHA256_SOURCE_VS = {
    # This is an example on how this would work with VirusShare
    "name": "VirusShare",
    "url": r"https://virusshare.com/apiv2/download?apikey=$VS_APIKEY&hash={HASH}",
    "replace_pattern": r"{HASH}"
}

EXAMPLE_SHA256_SOURCE_MWDB = {
    # This is an example on how this would work with MWDB
    "name": "MWDB",
    "url": r"https://mwdb.cert.pl/api/file/{HASH}/download",
    "replace_pattern": r"{HASH}",
    "headers": {
        "Authorization": "Bearer $MWDB_APIKEY"
    }
}

EXAMPLE_SHA256_SOURCE_FSIO = {
    # This is an example on how this would work with FileScanIO
    "name": "FileScanIO",
    "url": r"https://filescan.io/api/files/{HASH}?type=raw",
    "replace_pattern": r"{HASH}",
    "headers": {
        "X-Api-Key": "$FSIO_APIKEY"
    }
}

EXAMPLE_SHA256_SOURCE_MS = {
    # This is an example on how this would work with MalShare
    "name": "MalShare",
    "url": r"https://malshare.com/api.php?api_key=$MS_APIKEY&action=getfile&hash=${HASH}",
    "replace_pattern": r"{HASH}",
}

@odm.model(index=False, store=False,
           description="Minimum score value to get the specified verdict, otherwise the file is considered safe.")
class Verdicts(odm.Model):
    info: int = odm.Integer(description="Minimum score for the verdict to be Informational.")
    suspicious: int = odm.Integer(description="Minimum score for the verdict to be Suspicious.")
    highly_suspicious: int = odm.Integer(description="Minimum score for the verdict to be Highly Suspicious.")
    malicious: int = odm.Integer(description="Minimum score for the verdict to be Malicious.")


DEFAULT_VERDICTS = {
    'info': 0,
    'suspicious': 300,
    'highly_suspicious': 700,
    'malicious': 1000
}

METADATA_FIELDTYPE_MAP = {
    'date': odm.Date,
    'boolean': odm.Boolean,
    'keyword': odm.Keyword,
    'text': odm.Text,
    'ip': odm.IP,
    'domain': odm.Domain,
    'email': odm.Email,
    'uri': odm.URI,
    'integer': odm.Integer,
    'regex': odm.ValidatedKeyword,
    'enum': odm.Enum,
    'list': odm.List,
    'float': odm.Float
}


@odm.model(index=False, store=False, description="Metadata configuration")
class Metadata(odm.Model):
    validator_type: str = odm.Enum(values=METADATA_FIELDTYPE_MAP.keys(), default="str",
                                   description="Type of validation to apply to metadata value")
    validator_params: Dict[str, Any] = odm.Mapping(odm.Any(), default={},
                                                   description="Configuration parameters to apply to validator")
    suggestions: List[str] = odm.List(odm.Keyword(), default=[], description="List of suggestions for this field")
    suggestion_key: str = odm.Optional(odm.Keyword(), description="Key in redis where to get the suggestions from")
    default: Any = odm.Optional(odm.Keyword(description="Default value for the field"))
    required: bool = odm.Boolean(default=False, description="Is this field required?")
    aliases: List[str] = odm.List(odm.Keyword(), default=[],
                                  description="Field name aliases that map over to the field.")


@odm.model(index=False, store=False, description="Configuration for metadata compliance with APIs")
class MetadataConfig(odm.Model):
    archive: Dict[str, Metadata] = odm.Mapping(odm.Compound(Metadata),
                                               description="Metadata specification for archiving")
    submit: Dict[str, Metadata] = odm.Mapping(odm.Compound(Metadata),
                                              description="Metadata specification for submission")
    ingest: Dict[str, Dict[str, Metadata]] = odm.Mapping(odm.Mapping(odm.Compound(
        Metadata)), description="Metadata specification for certain ingestion based on ingest_type")
    strict_schemes: List[str] = odm.List(
        odm.Keyword(),
        default=[],
        description="A list of metadata schemes with strict rules (ie. no extra/unknown metadata). "
                    "Values can be: `archive`, `submit`, or one of the schemes under `ingest`.")


DEFAULT_METADATA_CONFIGURATION = {
    'archive': {},
    'submit': {},
    'ingest': {
        # Metadata rule for when: ingest_type: "INGEST", by default there are no rules set.
        "INGEST": {}
    }
}


@odm.model(index=True, store=False, description="Submission Parameters for profile")
class SubmissionProfileParams(odm.Model):
    classification = odm.Optional(odm.Classification(),
                                  description="Original classification of the submission")
    deep_scan = odm.Optional(odm.Boolean(), description="Should a deep scan be performed?")
    generate_alert = odm.Optional(odm.Boolean(), description="Should this submission generate an alert?")
    ignore_cache = odm.Optional(odm.Boolean(), description="Ignore the cached service results?")
    ignore_recursion_prevention = odm.Optional(odm.Boolean(),
                                               description="Should we ignore recursion prevention?")
    ignore_filtering = odm.Optional(odm.Boolean(), description="Should we ignore filtering services?")
    ignore_size = odm.Optional(odm.Boolean(), description="Ignore the file size limits?")
    max_extracted = odm.Optional(odm.Integer(), description="Max number of extracted files")
    max_supplementary = odm.Optional(odm.Integer(), description="Max number of supplementary files")
    priority = odm.Optional(odm.Integer(), description="Priority of the scan")
    services = odm.Optional(odm.Compound(ServiceSelection), description="Service selection")
    service_spec = odm.Optional(odm.Mapping(odm.Mapping(odm.Any())), index=False, store=False,
                                description="Service-specific parameters")
    auto_archive = odm.Optional(odm.Boolean(),
                                description="Does the submission automatically goes into the archive when completed?")
    delete_after_archive = odm.Optional(odm.Boolean(),
                                        description="When the submission is archived, should we delete it from hot storage right away?")
    ttl = odm.Optional(odm.Integer(), description="Time, in days, to live for this submission")
    type = odm.Optional(odm.Keyword(), description="Type of submission")
    use_archive_alternate_dtl = odm.Optional(odm.Boolean(),
                                             description="Should we use the alternate dtl while archiving?")


DEFAULT_RESTRICTED_PARAMS = {
    # Default privilege params that are used in all profiles
    "submission": ["ignore_recursion_prevention"],
    "APKaye": ["resubmit_apk_as_jar"],
    "AVClass": ["include_malpedia_dataset"],
    "CAPE": ["specific_image", "dll_function", "dump_memory", "force_sleepskip", "no_monitor", "simulate_user", "reboot", "arguments", "custom_options", "clock", "package", "specific_machine", "platform", "routing", "ignore_cape_cache", "hh_args", "monitored_and_unmonitored"],
    "ConfigExtractor": ["include_empty_config"],
    "DeobfuScripter": ["extract_original_iocs", "max_file_size"],
    "DocumentPreview": ["load_email_images", "save_ocr_output"],
    "EmlParser": ["extract_body_text", "save_emlparser_output"],
    "Extract": ["extract_executable_sections", "continue_after_extract", "use_custom_safelisting", "score_failed_password"],
    "FrankenStrings": ["max_file_size", "max_string_length"],
    "JsJaws": ["tool_timeout", "add_supplementary", "static_signatures", "display_iocs", "static_analysis_only", "ignore_stdout_limit", "no_shell_error", "browser", "wscript_only", "throw_http_exc", "download_payload", "extract_function_calls", "extract_eval_calls", "log_errors", "override_eval", "file_always_exists", "enable_synchrony"],
    "Overpower": ["tool_timeout", "add_supplementary", "fake_web_download"],
    "PDFId": ["carved_obj_size_limit"],
    "Pixaxe": ["save_ocr_output", "extract_ocr_uri"],
    "Suricata": ["extract_files"],
    "URLDownloader": ["regex_extract_filetype", "regex_supplementary_filetype", "extract_unmatched_filetype"],
    "XLMMacroDeobfuscator": ["start point"],
}


@odm.model(index=False, store=False, description="Configuration for defining submission profiles for basic users")
class SubmissionProfile(odm.Model):
    name = odm.Text(description="Submission profile name")
    display_name = odm.Text(description="Submission profile display name")
    classification = odm.ClassificationString(default=Classification.UNRESTRICTED,
                                              description="Submission profile classification")
    params = odm.Compound(SubmissionProfileParams, description="Default submission parameters for profile")
    restricted_params = odm.Mapping(odm.List(odm.Text()), default=DEFAULT_RESTRICTED_PARAMS,
                                    description="A list of parameters that can be configured for this profile. The keys are the service names or \"submission\" and the values are the parameters that cannot be configured by limited users.")
    description = odm.Optional(odm.Text(), description="A description of what the profile does")


DEFAULT_SUBMISSION_PROFILES = [
    {
        # Only perform static analysis
        "name": "static",
        "display_name": "Static Analysis",
        "params": {
            "services": {
                "excluded": ["Dynamic Analysis", "Internet Connected"],
                "selected": DEFAULT_SRV_SEL
            }
        },
        "description": "Analyze files using static analysis techniques and extract information from the file without executing it, such as metadata, strings, and structural information."
    },
    {
        # Perform static analysis along with dynamic analysis
        "name": "static_with_dynamic",
        "display_name": "Static + Dynamic Analysis",
        "params": {
            "services": {
                "excluded": ["Internet Connected"],
                "selected": DEFAULT_SRV_SEL + ["Dynamic Analysis"]
            }
        },
        "description": "Analyze files using static analysis techniques along with executing them in a controlled environment to observe their behavior and capture runtime activities, interactions with the system, network communications, and any malicious behavior exhibited by the file during execution."
    },
    {
        # Perform static analysis along with internet connected services
        "name": "static_with_internet",
        "display_name": "Internet-Connected Static Analysis",
        "params": {
            "services": {
                "excluded": ["Dynamic Analysis"],
                "selected": DEFAULT_SRV_SEL + ["Internet Connected"]
            },
        },
        "description": "Combine traditional static analysis techniques with internet-connected services to gather additional information and context about the file being analyzed."
    },
]

TEMPORARY_KEY_TYPE = [
    # Keep this key as submission wide list merging equal items
    'union',
    # Keep this key submission wide on a "last write wins" basis
    'overwrite',
]


@odm.model(index=False, store=False,
           description="Default values for parameters for submissions that may be overridden on a per submission basis")
class Submission(odm.Model):
    default_max_extracted: int = odm.Integer(description="How many extracted files may be added to a submission?")
    default_max_supplementary: int = odm.Integer(
        description="How many supplementary files may be added to a submission?")
    dtl: int = odm.Integer(min=0, description="Number of days submissions will remain in the system by default")
    emptyresult_dtl:  int = odm.Integer(min=0, description="Number of days emptyresult will remain in the system")
    max_dtl: int = odm.Integer(min=0, description="Maximum number of days submissions will remain in the system")
    max_extraction_depth: int = odm.Integer(description="Maximum files extraction depth")
    max_file_size: int = odm.long(description="Maximum size for files submitted in the system")
    max_metadata_length: int = odm.Integer(description="Maximum length for each metadata values")
    max_temp_data_length: int = odm.Integer(description="Maximum length for each temporary data values")
    metadata: MetadataConfig = odm.Compound(MetadataConfig, default=DEFAULT_METADATA_CONFIGURATION,
                                            description="Metadata compliance rules")
    sha256_sources: List[Sha256Source] = odm.List(
        odm.Compound(Sha256Source),
        default=[],
        description="List of external source to fetch file via their SHA256 hashes",
        deprecation="Use submission.file_sources which is an extension of this configuration")
    file_sources: List[FileSource] = odm.List(
        odm.Compound(FileSource),
        default=[],
        description="List of external source to fetch file")
    tag_types = odm.Compound(TagTypes, default=DEFAULT_TAG_TYPES,
                             description="Tag types that show up in the submission summary")
    verdicts = odm.Compound(Verdicts, default=DEFAULT_VERDICTS,
                            description="Minimum score value to get the specified verdict.")
    default_temporary_keys: dict[str, str] = odm.mapping(odm.enum(TEMPORARY_KEY_TYPE),
                                                         description="temporary_keys values for well known services.")
    temporary_keys: dict[str, str] = odm.mapping(odm.enum(TEMPORARY_KEY_TYPE),
                                                 description="Set the operation that will be used to update values "
                                                             "using this key in the temporary submission data.")
    profiles = odm.List(odm.Compound(SubmissionProfile),
                        description="Submission profiles with preset submission parameters")


DEFAULT_TEMPORARY_KEYS = {
    'passwords': 'union',
    'email_body': 'union',
}

DEFAULT_SUBMISSION = {
    'default_max_extracted': 500,
    'default_max_supplementary': 500,
    'dtl': 30,
    'emptyresult_dtl': 5,
    'max_dtl': 0,
    'max_extraction_depth': 6,
    'max_file_size': 104857600,
    'max_metadata_length': 4096,
    'max_temp_data_length': 4096,
    'metadata': DEFAULT_METADATA_CONFIGURATION,
    'sha256_sources': [],
    'file_sources': [],
    'tag_types': DEFAULT_TAG_TYPES,
    'verdicts': DEFAULT_VERDICTS,
    'default_temporary_keys': DEFAULT_TEMPORARY_KEYS,
    'temporary_keys': {},
    'profiles': DEFAULT_SUBMISSION_PROFILES
}


@odm.model(index=False, store=False, description="Configuration for connecting to a retrohunt service.")
class Retrohunt(odm.Model):
    enabled = odm.Boolean(default=False, description="Is the Retrohunt functionnality enabled on the frontend")
    dtl: int = odm.Integer(min=0, description="Number of days retrohunt jobs will remain in the system by default")
    max_dtl: int = odm.Integer(min=0, description="Maximum number of days retrohunt jobs will remain in the system")
    url = odm.Keyword(description="Base URL for service API")
    api_key = odm.Keyword(description="Service API Key")
    tls_verify = odm.Boolean(default=True, description="Should tls certificates be verified")


DEFAULT_RETROHUNT = {
    'enabled': False,
    'dtl': 30,
    'max_dtl': 0,
    'url': 'https://hauntedhouse:4443',
    'api_key': "ChangeThisDefaultRetroHuntAPIKey!",
    'tls_verify': True
}


@odm.model(index=False, store=False, description="Assemblyline Deployment Configuration")
class Config(odm.Model):
    auth: Auth = odm.compound(Auth, default=DEFAULT_AUTH, description="Authentication module configuration")
    core: Core = odm.compound(Core, default=DEFAULT_CORE, description="Core component configuration")
    datastore: Datastore = odm.compound(Datastore, default=DEFAULT_DATASTORE, description="Datastore configuration")
    datasources: Dict[str, Datasource] = odm.mapping(odm.compound(Datasource), default=DEFAULT_DATASOURCES,
                                                     description="Datasources configuration")
    filestore: Filestore = odm.compound(Filestore, default=DEFAULT_FILESTORE, description="Filestore configuration")
    logging: Logging = odm.compound(Logging, default=DEFAULT_LOGGING, description="Logging configuration")
    retrohunt: Retrohunt = odm.Compound(Retrohunt, default=DEFAULT_RETROHUNT,
                                        description="Retrohunt configuration for the frontend and server.")
    services: Services = odm.compound(Services, default=DEFAULT_SERVICES, description="Service configuration")
    submission: Submission = odm.compound(Submission, default=DEFAULT_SUBMISSION,
                                          description="Options for how submissions will be processed")
    system: System = odm.compound(System, default=DEFAULT_SYSTEM, description="System configuration")
    ui: UI = odm.compound(UI, default=DEFAULT_UI, description="UI configuration parameters")


DEFAULT_CONFIG = {
    "auth": DEFAULT_AUTH,
    "core": DEFAULT_CORE,
    "datastore": DEFAULT_DATASTORE,
    "datasources": DEFAULT_DATASOURCES,
    "filestore": DEFAULT_FILESTORE,
    "logging": DEFAULT_LOGGING,
    "retrohunt": DEFAULT_RETROHUNT,
    "services": DEFAULT_SERVICES,
    "submission": DEFAULT_SUBMISSION,
    "system": DEFAULT_SYSTEM,
    "ui": DEFAULT_UI,
}


if __name__ == "__main__":
    # When executed, the config model will print the default values of the configuration
    import yaml
    print(yaml.safe_dump(DEFAULT_CONFIG))
