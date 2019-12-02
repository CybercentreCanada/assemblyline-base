from assemblyline import odm

MSG_TYPES = {"ScalerStatusHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.scaler_status_heartbeat.ScalerStatusMessage"


@odm.model()
class Status(odm.Model):
    running = odm.Integer()
    target = odm.Integer()
    minimum = odm.Integer()
    maximum = odm.Integer()
    dynamic_maximum = odm.Integer()
    queue = odm.Integer()
    pressure = odm.Float()
    duty_cycle = odm.Float()


@odm.model()
class Heartbeat(odm.Model):
    service_name = odm.Keyword()
    metrics = odm.Compound(Status)


@odm.model()
class ScalerStatusMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ScalerStatusHeartbeat")
    sender = odm.Keyword()
