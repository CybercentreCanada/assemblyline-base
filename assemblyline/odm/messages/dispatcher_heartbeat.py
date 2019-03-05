from assemblyline import odm

MSG_TYPES = {"DispatcherHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.dispatcher_heartbeat.DispatcherMessage"


@odm.model()
class Queues(odm.Model):
    control = odm.Integer()
    ingest = odm.Integer()
    response = odm.Integer()


@odm.model()
class Inflight(odm.Model):
    max = odm.Integer()
    outstanding = odm.Integer()


@odm.model()
class Heartbeat(odm.Model):
    count = odm.Integer()
    inflight = odm.Compound(Inflight)
    queues = odm.Compound(Queues)


@odm.model()
class DispatcherMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="DispatcherHeartbeat")
    sender = odm.Keyword()
