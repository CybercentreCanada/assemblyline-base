from assemblyline import odm

ACL = {"R", "W", "E"}


@odm.model(index=True, store=True)
class ApiKey(odm.Model):
    acl = odm.List(odm.Enum(values=ACL))  # Access control list for the apikey
    name = odm.Keyword()                  # Name of the apikey
    password = odm.Keyword()              # BCrypt hash of the password for the apikey


@odm.model(index=True, store=True)
class User(odm.Model):
    agrees_with_tos = odm.Boolean()                                   # Those the user agree with terms of service
    api_quota = odm.Integer()                                         # Max number of concurrent API requests
    apikeys = odm.List(odm.Compound(ApiKey))                          # List of apikeys
    avatar = odm.Keyword(store=False, index=False)                    # Avatar for the user
    can_impersonate = odm.Boolean(default=False)                      # Is the user allow to query on behalf of others
    classification = odm.Classification(is_user_classification=True)  # Max classification for the user
    dn = odm.Keyword()                                                # User certificate DN
    email = odm.Keyword()                                             # User's email address
    groups = odm.List(odm.Keyword())                                  # List of groups the user submits to
    is_active = odm.Boolean()                                         # is the user active
    is_admin = odm.Boolean()                                          # is the user an admin
    name = odm.Keyword()                                              # Full name of the user
    otp_sk = odm.Keyword()                                            # Secret key to generate one time passwords
    password = odm.Keyword()                                          # BCrypt hash of the user's password
    submission_quota = odm.Integer()                                  # Maximum number of concurrent submissions
    u2f_devices = odm.Mapping(odm.Keyword())                          # Map of u2f security tokens
    uname = odm.Keyword()                                             # Username
