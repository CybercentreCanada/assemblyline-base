from assemblyline import odm

MSG_TYPES = {"DispHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.dispatcher.DispatcherMessage"


@odm.model()
class Resources(odm.Model):
    cpu_usage = odm.Float()
    disk_usage_free = odm.Integer()
    disk_usage_percent = odm.Float()
    mem_usage = odm.Float()


@odm.model()
class Queues(odm.Model):
    control = odm.Integer()
    ingest = odm.Integer()
    max_inflight = odm.Integer()
    response = odm.Integer()


@odm.model()
class HostInfo(odm.Model):
    host = odm.Keyword()
    ip = odm.Keyword()
    mac_address = odm.Keyword()


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
    body = odm.Compound(Heartbeat)
    obj_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="DispHeartbeat")
    sender = odm.Keyword()
