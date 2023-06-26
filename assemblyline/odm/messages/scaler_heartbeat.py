from assemblyline import odm
from assemblyline.odm.models.service import SUPPORTED_OS

MSG_TYPES = {"ScalerHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.scaler_heartbeat.ScalerMessage"

@odm.model(description="Metrics")
class Metrics(odm.Model):
    memory_free = odm.Float(description="Amount of free memory")
    cpu_free = odm.Float(description="Amount of free CPU")
    memory_total = odm.Float(description="Amount of total memory")
    cpu_total = odm.Float(description="Amount of total CPU")


@odm.model(description="Heartbeat Model")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of instances")
    metrics = odm.Compound(Metrics, description="Metrics")
    operating_system = odm.Enum(values=SUPPORTED_OS, default='linux', description="Operating System")


@odm.model(description="Model of Scaler Heartbeat Message")
class ScalerMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class of message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ScalerHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
