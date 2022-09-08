from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

ACL = {"R", "W", "E"}
SCOPES = {"r", "w", "rw"}
USER_TYPES = {
    "admin",               # Perform administrative tasks
    "signature_manager",   # Manage signatures and sources
    "signature_importer",  # Save signatures in the system
    "user",                # Has all task following specific roles
    # Task specific roles
    "file_view",           # View files in the file viewer
    "file_download",       # Download files from the system
    "alert_view",          # View alerts in the system
    "alert_manage",        # Modify labels, priority, status, verdict or owner of alerts
    "submission_delete",   # Delete submission from the system
    "submission_start",    # Start a submission in the system
    "submission_view",     # View submission's results
    "submission_manage",   # Set user verdict on submissions
    "submission_replay",   # Allow submission to be replayed on another server
    "workflow_manager",    # Manage (add/delete) workflows
    "safelist_manager"     # Manade (add/delete) safelist items
}


@odm.model(index=False, store=False, description="Model for API keys")
class ApiKey(odm.Model):
    acl = odm.List(odm.Enum(values=ACL), description="Access Control List for the API key")
    password = odm.Keyword(description="BCrypt hash of the password for the apikey")


@odm.model(index=False, store=False, description="Model of Apps used of OBO (On Behalf Of)")
class Apps(odm.Model):
    client_id = odm.Keyword(description="Username allowed to impersonate the current user")
    netloc = odm.Keyword(description="DNS hostname for the server")
    scope = odm.Enum(values=SCOPES, description="Scope of access for the API key")
    server = odm.Keyword(description="Name of the server that has access")


@odm.model(index=True, store=True, description="Model of User")
class User(odm.Model):
    agrees_with_tos = odm.Optional(
        odm.Date(index=False, store=False),
        description="Date the user agree with terms of service")
    api_quota = odm.Integer(default=10, store=False, description="Maximum number of concurrent API requests")
    apikeys = odm.Mapping(odm.Compound(ApiKey), default={}, index=False, store=False, description="Mapping of API keys")
    apps = odm.Mapping(odm.Compound(Apps), default={}, index=False, store=False,
                       description="Applications with access to the account")
    can_impersonate = odm.Boolean(default=False, index=False, store=False,
                                  description="Allowed to query on behalf of others?")
    classification = odm.Classification(is_user_classification=True, copyto="__text__",
                                        default=Classification.UNRESTRICTED,
                                        description="Maximum classification for the user")
    dn = odm.Optional(odm.Keyword(store=False, copyto="__text__"), description="User's LDAP DN")
    email = odm.Optional(odm.Email(copyto="__text__"), description="User's email address")
    groups = odm.List(odm.Keyword(), copyto="__text__", default=["USERS"],
                      description="List of groups the user submits to")
    is_active = odm.Boolean(default=True, description="Is the user active?")
    name = odm.Keyword(copyto="__text__", description="Full name of the user")
    otp_sk = odm.Optional(
        odm.Keyword(index=False, store=False),
        description="Secret key to generate one time passwords")
    password = odm.Keyword(index=False, store=False, description="BCrypt hash of the user's password")
    submission_quota = odm.Integer(default=5, store=False, description="Maximum number of concurrent submissions")
    type = odm.List(odm.Enum(values=USER_TYPES), default=['user'], description="Type of user")
    security_tokens = odm.Mapping(odm.Keyword(), index=False, store=False, default={},
                                  description="Map of security tokens")
    uname = odm.Keyword(copyto="__text__", description="Username")
