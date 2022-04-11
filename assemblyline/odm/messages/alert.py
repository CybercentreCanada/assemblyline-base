from assemblyline import odm
from assemblyline.odm.models.alert import Alert

MSG_TYPES = {"AlertCreated", "AlertUpdated"}
LOADER_CLASS = "assemblyline.odm.messages.alert.AlertMessage"


@odm.model(description="Model of Alert Message")
class AlertMessage(odm.Model):
    msg = odm.Compound(Alert, description="Message of alert")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for messages")
    msg_type = odm.Enum(values=MSG_TYPES, default="AlertCreated", description="Type of Message")
    sender = odm.Keyword(description="Sender of message")
