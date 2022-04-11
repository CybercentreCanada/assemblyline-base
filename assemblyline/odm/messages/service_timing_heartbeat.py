from assemblyline import odm
from assemblyline.odm.messages import PerformanceTimer

MSG_TYPES = {"ServiceTimingHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.service_heartbeat.ServiceTimingMessage"


@odm.model(description="Timing Metrics")
class Metrics(odm.Model):
    execution = PerformanceTimer(description="Excution time")
    execution_count = odm.Integer(description="Number of executes")
    idle = PerformanceTimer(description="Idle time")
    idle_count = odm.Integer(description="Number of idles")


@odm.model(description="Hearbeat Model")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of instances")
    metrics = odm.Compound(Metrics, description="Metrics")
    queue = odm.Integer(description="Queue size")
    service_name = odm.Keyword(description="Name of service")


@odm.model(description="Model of Service Timing Heartbeat Message")
class ServiceTimingMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ServiceTimingHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
