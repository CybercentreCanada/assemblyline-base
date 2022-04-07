from assemblyline import odm
from assemblyline.odm.messages import PerformanceTimer

MSG_TYPES = {"WatcherHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.watcher_heartbeat.WatcherMessage"


@odm.model()
class Metrics(odm.Model):
    expired = odm.Integer()
    cpu_seconds = PerformanceTimer()
    cpu_seconds_count = odm.Integer()
    busy_seconds = PerformanceTimer()
    busy_seconds_count = odm.Integer()


@odm.model()
class Heartbeat(odm.Model):
    instances = odm.Integer()
    metrics = odm.Compound(Metrics)
    watching = odm.Integer()


@odm.model()
class WatcherMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="WatcherHeartbeat")
    sender = odm.Keyword()
