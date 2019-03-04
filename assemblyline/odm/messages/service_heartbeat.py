from assemblyline import odm
from assemblyline.odm.common import HostInfo, Resources

MSG_TYPES = {"ServiceHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.old.service.ServiceMessage"


@odm.model()
class Counters(odm.Model):
    cached = odm.Integer()
    failed = odm.Integer()
    processed = odm.Integer()


@odm.model()
class Heartbeat(odm.Model):
    counters = odm.Compound(Counters)
    service_name = odm.Keyword()
    queue = odm.Integer()


@odm.model()
class ServiceMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ServiceHeartbeat")
    sender = odm.Keyword()
