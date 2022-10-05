from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.str_utils import StringTable

Classification = forge.get_classification()

TYPES = StringTable('TYPES', [
    ("admin", 0),
    ("user", 1),
    ("signature_manager", 2),
    ("signature_importer", 3),
    ("viewer", 4),
    ("submitter", 5),
    ("custom", 6)
])

ROLES = StringTable('ROLES', [
    ("alert_manage", 0),
    ("alert_view", 1),
    ("apikey_access", 2),
    ("bundle_download", 3),
    ("file_detail", 4),
    ("file_download", 5),
    ("heuristic_view", 6),
    ("obo_access", 7),
    ("replay_trigger", 8),
    ("safelist_view", 9),
    ("safelist_manage", 10),
    ("signature_download", 11),
    ("signature_view", 12),
    ("submission_create", 13),
    ("submission_delete", 14),
    ("submission_manage", 15),
    ("submission_view", 16),
    ("workflow_manage", 17),
    ("workflow_view", 18),
    ("administration", 19),
    ("replay_system", 20),
    ("signature_import", 21),
    ("signature_manage", 22),
    ("archive_view", 23),
    ("archive_manage", 24),
    ("archive_trigger", 25),
])


ACL = {"R", "W", "E"}
SCOPES = {"r", "w", "rw"}
USER_TYPES = [
    TYPES.admin,               # Perform administartive task and has access to all roles
    TYPES.user,                # Normal user of the system
    TYPES.signature_manager,   # Super user that also has access to roles for managing signatures in the system
    TYPES.signature_importer,  # Has access to roles for importing signatures in the system
    TYPES.viewer,              # User that can only view the data
    TYPES.submitter,           # User that can only start submissions
    TYPES.custom,              # Has custom roles selected
]

USER_ROLES_BASIC = {
    ROLES.alert_manage,        # Modify labels, priority, status, verdict or owner of alerts
    ROLES.alert_view,          # View alerts in the system
    ROLES.archive_trigger,     # Send Submission, files and results to the archive
    ROLES.archive_view,        # View archived data in the system
    ROLES.archive_manage,      # Modify attributes of archived Submissions/Files/Results
    ROLES.apikey_access,       # Allow access via API keys
    ROLES.bundle_download,     # Create bundle of a submission
    ROLES.file_detail,         # View files in the file viewer
    ROLES.file_download,       # Download files from the system
    ROLES.heuristic_view,      # View heuristics of the system
    ROLES.obo_access,          # Allow access via On Behalf Off tokens
    ROLES.replay_trigger,      # Allow submission to be replayed on another server
    ROLES.safelist_view,       # View safelist items
    ROLES.safelist_manage,     # Manade (add/delete) safelist items
    ROLES.signature_download,  # Download signatures from the system
    ROLES.signature_view,      # View signatures
    ROLES.submission_create,   # Create a submission in the system
    ROLES.submission_delete,   # Delete submission from the system
    ROLES.submission_manage,   # Set user verdict on submissions
    ROLES.submission_view,     # View submission's results
    ROLES.workflow_manage,     # Manage (add/delete) workflows
    ROLES.workflow_view,       # View workflows
}

USER_ROLES = USER_ROLES_BASIC.union({
    ROLES.administration,      # Perform administrative tasks
    ROLES.replay_system,       # Manage status of file/submission/alerts during the replay process
    ROLES.signature_import,    # Import signatures in the system
    ROLES.signature_manage,    # Manage signatures sources in the system
})

USER_TYPE_DEP = {
    TYPES.admin: USER_ROLES,
    TYPES.signature_importer: {
        ROLES.safelist_manage,
        ROLES.signature_download,
        ROLES.signature_import,
        ROLES.signature_view
    },
    TYPES.signature_manager: USER_ROLES_BASIC.union({
        ROLES.signature_manage
    }),
    TYPES.user: USER_ROLES_BASIC,
    TYPES.viewer: {
        ROLES.alert_view,
        ROLES.apikey_access,
        ROLES.file_detail,
        ROLES.obo_access,
        ROLES.heuristic_view,
        ROLES.safelist_view,
        ROLES.signature_view,
        ROLES.submission_view,
        ROLES.workflow_view,
    },
    TYPES.submitter: {
        ROLES.apikey_access,
        ROLES.obo_access,
        ROLES.submission_create,
        ROLES.replay_trigger,
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
