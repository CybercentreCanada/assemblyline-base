from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.str_utils import StringTable
from assemblyline.odm.models.user import ACL_MAP, USER_ROLES


APIKEY_ID_FORMAT = "{}+{}"




@odm.model(index=True, store=True, description="Model of Apikey")
class Apikey(odm.Model):
    acl = odm.List(odm.Enum(values=ACL_MAP.keys()), description="Access Control List for the API key")
    password = odm.Keyword(description="BCrypt hash of the password for the apikey")
    roles = odm.List(odm.Enum(values=USER_ROLES), default=[], description="List of roles tied to the API key")
    uname = odm.Keyword(copyto="__text__", description="Username")
    key_name = odm.Keyword(copyto="__text__", description="Name of the key")
    creation_date = odm.Date(default="NOW", description="The date this API key is created.")
    expiry_ts = odm.Optional(odm.Date(), description="Expiry timestamp.")
    last_used =odm.Optional(odm.Date(), description="The last time this API key was used.")

def get_apikey_id(keyname, uname):
    return APIKEY_ID_FORMAT.format(keyname, uname)
