from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.str_utils import StringTable

Classification = forge.get_classification()

TYPES = StringTable('TYPES', [
    ('ADMIN', "admin"),
    ('USER', "user"),
    ('SIGNATURE_MANAGER', "signature_manager"),
    ('SIGNATURE_IMPORTER', "signature_importer"),
    ('VIEWER', "viewer"),
    ('SUBMITTER', "submitter"),
    ('CUSTOM', "custom")
])

ROLES = StringTable('ROLES', [
    ("ALERT_MANAGE", "alert_manage"),
    ("ALERT_VIEW", "alert_view"),
    ("APIKEY_ACCESS", "apikey_access"),
    ("BUNDLE_DOWNLOAD", "bundle_download"),
    ("FILE_DETAIL", "file_detail"),
    ("FILE_DOWNLOAD", "file_download"),
    ("HEURISTIC_VIEW", "heuristic_view"),
    ("OBO_ACCESS", "obo_access"),
    ("REPLAY_TRIGGER", "replay_trigger"),
    ("SAFELIST_VIEW", "safelist_view"),
    ("SAFELIST_MANAGE", "safelist_manage"),
    ("SIGNATURE_DOWNLOAD", "signature_download"),
    ("SIGNATURE_VIEW", "signature_view"),
    ("SUBMISSION_CREATE", "submission_create"),
    ("SUBMISSION_DELETE", "submission_delete"),
    ("SUBMISSION_MANAGE", "submission_manage"),
    ("SUBMISSION_VIEW", "submission_view"),
    ("WORKFLOW_MANAGE", "workflow_manage"),
    ("WORKFLOW_VIEW", "workflow_view"),
    ("ADMINISTRATION", "administration"),
    ("REPLAY_SYSTEM", "replay_system"),
    ("SIGNATURE_IMPORT", "signature_import"),
    ("SIGNATURE_MANAGE", "signature_manage"),
])


ACL = {"R", "W", "E"}
SCOPES = {"r", "w", "rw"}
USER_TYPES = [
    TYPES.ADMIN,               # Perform administartive task and has access to all roles
    TYPES.USER,                # Normal user of the system
    TYPES.SIGNATURE_MANAGER,   # Super user that also has access to roles for managing signatures in the system
    TYPES.SIGNATURE_IMPORTER,  # Has access to roles for importing signatures in the system
    TYPES.VIEWER,              # User that can only view the data
    TYPES.SUBMITTER,           # User that can only start submissions
    TYPES.CUSTOM,              # Has custom roles selected
]

USER_ROLES_BASIC = {
    ROLES.ALERT_MANAGE,        # Modify labels, priority, status, verdict or owner of alerts
    ROLES.ALERT_VIEW,          # View alerts in the system
    ROLES.APIKEY_ACCESS,       # Allow access via API keys
    ROLES.BUNDLE_DOWNLOAD,     # Create bundle of a submission
    ROLES.FILE_DETAIL,         # View files in the file viewer
    ROLES.FILE_DOWNLOAD,       # Download files from the system
    ROLES.HEURISTIC_VIEW,      # View heuristics of the system
    ROLES.OBO_ACCESS,          # Allow access via On Behalf Off tokens
    ROLES.REPLAY_TRIGGER,      # Allow submission to be replayed on another server
    ROLES.SAFELIST_VIEW,       # View safelist items
    ROLES.SAFELIST_MANAGE,     # Manade (add/delete) safelist items
    ROLES.SIGNATURE_DOWNLOAD,  # Download signatures from the system
    ROLES.SIGNATURE_VIEW,      # View signatures
    ROLES.SUBMISSION_CREATE,   # Create a submission in the system
    ROLES.SUBMISSION_DELETE,   # Delete submission from the system
    ROLES.SUBMISSION_MANAGE,   # Set user verdict on submissions
    ROLES.SUBMISSION_VIEW,     # View submission's results
    ROLES.WORKFLOW_MANAGE,     # Manage (add/delete) workflows
    ROLES.WORKFLOW_VIEW,       # View workflows
}

USER_ROLES = USER_ROLES_BASIC.union({
    ROLES.ADMINISTRATION,      # Perform administrative tasks
    ROLES.REPLAY_SYSTEM,       # Manage status of file/submission/alerts during the replay process
    ROLES.SIGNATURE_IMPORT,    # Import signatures in the system
    ROLES.SIGNATURE_MANAGE,    # Manage signatures sources in the system
})

USER_TYPE_DEP = {
    TYPES.ADMIN: USER_ROLES,
    TYPES.SIGNATURE_IMPORTER: {
        ROLES.SAFELIST_MANAGE,
        ROLES.SIGNATURE_DOWNLOAD,
        ROLES.SIGNATURE_IMPORT,
        ROLES.SIGNATURE_VIEW
    },
    TYPES.SIGNATURE_MANAGER: USER_ROLES_BASIC.union({
        ROLES.SIGNATURE_MANAGE
    }),
    TYPES.USER: USER_ROLES_BASIC,
    TYPES.VIEWER: {
        ROLES.ALERT_VIEW,
        ROLES.APIKEY_ACCESS,
        ROLES.FILE_DETAIL,
        ROLES.OBO_ACCESS,
        ROLES.HEURISTIC_VIEW,
        ROLES.SAFELIST_VIEW,
        ROLES.SIGNATURE_VIEW,
        ROLES.SUBMISSION_VIEW,
        ROLES.WORKFLOW_VIEW,
    },
    TYPES.SUBMITTER: {
        ROLES.APIKEY_ACCESS,
        ROLES.OBO_ACCESS,
        ROLES.SUBMISSION_CREATE,
        ROLES.REPLAY_TRIGGER,
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
