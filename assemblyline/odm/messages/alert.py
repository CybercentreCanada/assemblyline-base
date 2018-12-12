from assemblyline import odm
from assemblyline.odm.models.alert import Alert

MSG_TYPES = {"AlertCreated", "AlertModified"}
LOADER_CLASS = "assemblyline.odm.messages.alert.AlertMessage"


@odm.model()
class AlertMessage(odm.Model):
    body = odm.Compound(Alert)
    obj_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="AlertCreated")
    sender = odm.Keyword()
