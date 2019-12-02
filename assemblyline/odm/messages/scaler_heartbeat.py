from assemblyline import odm

MSG_TYPES = {"ScalerHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.scaler_heartbeat.ScalerMessage"


@odm.model()
class Metrics(odm.Model):
    memory_free = odm.Float()
    cpu_free = odm.Float()
    memory_total = odm.Float()
    cpu_total = odm.Float()


@odm.model()
class Heartbeat(odm.Model):
    instances = odm.Integer()
    metrics = odm.Compound(Metrics)


@odm.model()
class ScalerMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ScalerHeartbeat")
    sender = odm.Keyword()
