from assemblyline import odm
from assemblyline.odm.messages import Resources

MSG_TYPES = {"CtlHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.controller.ControllerMessage"


@odm.model()
class Heartbeat(odm.Model):
    mac = odm.Keyword()
    resources = odm.Compound(Resources)
    time = odm.Date()


@odm.model()
class ControllerMessage(odm.Model):
    body = odm.Compound(Heartbeat)
    obj_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="CtlHeartbeat")
    sender = odm.Keyword()
