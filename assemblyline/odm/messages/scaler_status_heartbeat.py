from assemblyline import odm

MSG_TYPES = {"ScalerStatusHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.scaler_status_heartbeat.ScalerStatusMessage"


@odm.model(description="Service Status Model")
class Status(odm.Model):
    running = odm.Integer(description="Number of instances running")
    target = odm.Integer(description="Target scaling for service")
    minimum = odm.Integer(description="Minimum number of instances")
    maximum = odm.Integer(description="Maximum number of instances")
    dynamic_maximum = odm.Integer(description="Dynamic maximum number of instances")
    queue = odm.Integer(description="Service queue")
    pressure = odm.Float(description="Service pressure")
    duty_cycle = odm.Float(description="Duty Cycle")


@odm.model(description="Hearbeat Model")
class Heartbeat(odm.Model):
    service_name = odm.Keyword(description="Name of service")
    metrics = odm.Compound(Status, description="Status of service")


@odm.model(description="Model of Scaler's Status Heartbeat Message")
class ScalerStatusMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ScalerStatusHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
