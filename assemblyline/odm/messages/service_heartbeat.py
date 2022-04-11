from assemblyline import odm

MSG_TYPES = {"ServiceHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.service_heartbeat.ServiceMessage"


@odm.model(description="Service Metrics")
class Metrics(odm.Model):
    cache_hit = odm.Integer(description="Number of cache hits")
    cache_miss = odm.Integer(description="Number of cache misses")
    cache_skipped = odm.Integer(description="Number of cache skips")
    execute = odm.Integer(description="Number of service executes")
    fail_recoverable = odm.Integer(description="Number of recoverable fails")
    fail_nonrecoverable = odm.Integer(description="Number of non-recoverable fails")
    scored = odm.Integer(description="Number of tasks scored")
    not_scored = odm.Integer(description="Number of tasks not scored")


@odm.model(description="Service Activity")
class Activity(odm.Model):
    busy = odm.Integer(description="Number of busy instances")
    idle = odm.Integer(description="Number of idle instances")


@odm.model(description="Heartbeat Model")
class Heartbeat(odm.Model):
    activity = odm.Compound(Activity, description="Service activity")
    instances = odm.Integer(description="Service instances")
    metrics = odm.Compound(Metrics, description="Service metrics")
    queue = odm.Integer(description="Service queue")
    service_name = odm.Keyword(description="Service name")


@odm.model(description="Model of Service Heartbeat Message")
class ServiceMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ServiceHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
