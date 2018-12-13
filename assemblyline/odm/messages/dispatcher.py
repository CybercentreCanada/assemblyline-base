from assemblyline import odm
from assemblyline.odm.common import Resources, HostInfo

MSG_TYPES = {"DispatcherHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.dispatcher.DispatcherMessage"


@odm.model()
class Queues(odm.Model):
    control = odm.Integer()
    ingest = odm.Integer()
    max_inflight = odm.Integer()
    response = odm.Integer()


@odm.model()
class ServiceTimming(odm.Model):
    last_heartbeat_at = odm.Float()
    last_result_at = odm.Float()


@odm.model()
class ServiceDetail(odm.Model):
    accepts = odm.Keyword()
    details = odm.Compound(ServiceTimming)
    is_up = odm.Boolean()


@odm.model()
class Heartbeat(odm.Model):
    entries = odm.Integer()
    errors = odm.Integer()
    hostinfo = odm.Compound(HostInfo)
    queues = odm.Compound(Queues)
    resources = odm.Compound(Resources)
    results = odm.Integer()
    services = odm.Mapping(odm.Compound(ServiceDetail))
    shard = odm.Integer(default=0)


@odm.model()
class DispatcherMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="DispatcherHeartbeat")
    sender = odm.Keyword()
