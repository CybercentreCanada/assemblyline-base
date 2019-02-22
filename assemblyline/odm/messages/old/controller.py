from assemblyline import odm
from assemblyline.odm.common import Resources

MSG_TYPES = {"ControllerHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.old.controller.ControllerMessage"


@odm.model()
class Heartbeat(odm.Model):
    mac = odm.Keyword()
    resources = odm.Compound(Resources)
    time = odm.Date()


@odm.model()
class ControllerMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ControllerHeartbeat")
    sender = odm.Keyword()
