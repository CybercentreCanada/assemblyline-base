from assemblyline import odm
from . import PerformanceTimer

MSG_TYPES = {"DispatcherHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.dispatcher_heartbeat.DispatcherMessage"


@odm.model()
class Queues(odm.Model):
    ingest = odm.Integer()
    start = odm.List(odm.Integer())
    result = odm.List(odm.Integer())
    command = odm.List(odm.Integer())


@odm.model()
class Inflight(odm.Model):
    max = odm.Integer()
    outstanding = odm.Integer()
    per_instance = odm.List(odm.Integer())


@odm.model()
class Metrics(odm.Model):
    files_completed = odm.Integer()
    submissions_completed = odm.Integer()
    service_timeouts = odm.Integer()
    cpu_seconds = PerformanceTimer()
    cpu_seconds_count = odm.Integer()
    busy_seconds = PerformanceTimer()
    busy_seconds_count = odm.Integer()


@odm.model()
class Heartbeat(odm.Model):
    inflight = odm.Compound(Inflight)
    instances = odm.Integer()
    metrics = odm.Compound(Metrics)
    queues = odm.Compound(Queues)
    component = odm.Keyword()


@odm.model()
class DispatcherMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="DispatcherHeartbeat")
    sender = odm.Keyword()
