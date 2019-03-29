from assemblyline import odm

MSG_TYPES = {"ServiceTimingHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.service_heartbeat.ServiceTimingMessage"


@odm.model()
class Metrics(odm.Model):
    execution = odm.Integer()
    execution_count = odm.Integer()
    idle = odm.Integer()
    idle_count = odm.Integer()


@odm.model()
class Heartbeat(odm.Model):
    instances = odm.Integer()
    metrics = odm.Compound(Metrics)
    service_name = odm.Keyword()


@odm.model()
class ServiceTimingMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ServiceTimingHeartbeat")
    sender = odm.Keyword()
