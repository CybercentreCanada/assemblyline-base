from assemblyline import odm
from assemblyline.odm.messages import PerformanceTimer

MSG_TYPES = {"DispatcherHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.dispatcher_heartbeat.DispatcherMessage"


@odm.model(description="Queue Model")
class Queues(odm.Model):
    ingest = odm.Integer(description="Number of submissions in ingest queue")
    start = odm.List(odm.Integer(), description="Number of submissions that started")
    result = odm.List(odm.Integer(), description="Number of results in queue")
    command = odm.List(odm.Integer(), description="Number of commands in queue")


@odm.model(description="Inflight Model")
class Inflight(odm.Model):
    max = odm.Integer(description="Maximum number of submissions")
    outstanding = odm.Integer(description="Number of outstanding submissions")
    per_instance = odm.List(odm.Integer(), description="Number of submissions per Dispatcher instance")


@odm.model(description="Metrics Model")
class Metrics(odm.Model):
    files_completed = odm.Integer(description="Number of files completed")
    submissions_completed = odm.Integer(description="Number of submissions completed")
    service_timeouts = odm.Integer(description="Number of service timeouts")
    cpu_seconds = PerformanceTimer(description="CPU time")
    cpu_seconds_count = odm.Integer(description="CPU count")
    busy_seconds = PerformanceTimer(description="Busy CPU time")
    busy_seconds_count = odm.Integer(description="Busy CPU count")
    save_queue = odm.Integer(description="Processed submissions waiting to be saved")
    error_queue = odm.Integer(description="Errors waiting to be saved")


@odm.model(description="Heartbeat Model")
class Heartbeat(odm.Model):
    inflight = odm.Compound(Inflight, description="Inflight submissions")
    instances = odm.Integer(description="Number of instances")
    metrics = odm.Compound(Metrics, description="Dispatcher metrics")
    queues = odm.Compound(Queues, description="Dispatcher queues")
    component = odm.Keyword(description="Component name")


@odm.model(description="Model of Dispatcher Heartbeat Messages")
class DispatcherMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="DispatcherHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
