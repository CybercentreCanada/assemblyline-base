from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

ACL = {"R", "W", "E"}
SCOPES = {"r", "w", "rw"}
USER_TYPES = [
    "admin",               # Perform administartive task and has access to all roles
    "user",                # Normal user of the system
    "signature_manager",   # Super user that also has access to roles for managing signatures in the system
    "signature_importer",  # Has access to roles for importing signatures in the system
    "viewer",              # User that can only view the data
    "submitter",           # User that can only start submissions
    "custom",              # Has custom roles selected
]

USER_ROLES_BASIC = {
    "alert_manage",        # Modify labels, priority, status, verdict or owner of alerts
    "alert_view",          # View alerts in the system
    "apikey_access",       # Allow access via API keys
    "bundle_download",     # Create bundle of a submission
    "file_detail",         # View files in the file viewer
    "file_download",       # Download files from the system
    "heuristic_view",      # View heuristics of the system
    "obo_access",          # Allow access via On Behalf Off tokens
    "replay_trigger",      # Allow submission to be replayed on another server
    "safelist_view",       # View safelist items
    "safelist_manage",     # Manade (add/delete) safelist items
    "signature_download",  # Download signatures from the system
    "signature_view",      # View signatures
    "submission_create",   # Create a submission in the system
    "submission_delete",   # Delete submission from the system
    "submission_manage",   # Set user verdict on submissions
    "submission_view",     # View submission's results
    "workflow_manage",     # Manage (add/delete) workflows
    "workflow_view",       # View workflows
}

USER_ROLES = USER_ROLES_BASIC.union({
    "administration",      # Perform administrative tasks
    "replay_system",       # Manage status of file/submission/alerts during the replay process
    "signature_import",    # Import signatures in the system
    "signature_manage",    # Manage signatures sources in the system
})

USER_TYPE_DEP = {
    "admin": USER_ROLES,
    "signature_importer": {
        "safelist_manage",
        "signature_download",
        "signature_import",
        "signature_view"
    },
    "signature_manager": USER_ROLES_BASIC.union({
        "signature_manage"
    }),
    "user": USER_ROLES_BASIC,
    "viewer": {
        "alert_view",
        "apikey_access",
        "file_detail",
        "obo_access",
        "heuristic_view",
        "safelist_view",
        "signature_view",
        "submission_view",
        "workflow_view",
    },
    "submitter": {
        "apikey_access",
        "obo_access",
        "submission_create",
        "replay_trigger",
    }
}


def load_roles(types, curRoles):
    # Check if we have current roles first
    if curRoles:
        return curRoles

    # Otherwise load the roles from the user type
    roles = set({})
    for user_type in USER_TYPE_DEP.keys():
        if user_type in types:
            roles = roles.union(USER_TYPE_DEP[user_type])

    # Return roles as a list
    return list(roles)


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
    roles = odm.List(odm.Enum(values=USER_ROLES), default=[], description="Default roles for user")
    security_tokens = odm.Mapping(odm.Keyword(), index=False, store=False, default={},
                                  description="Map of security tokens")
    uname = odm.Keyword(copyto="__text__", description="Username")
