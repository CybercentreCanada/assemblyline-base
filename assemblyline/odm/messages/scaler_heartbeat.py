from assemblyline import odm

MSG_TYPES = {"ScalerHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.scaler_heartbeat.ScalerMessage"


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
class Metrics(odm.Model):
    memory_free = odm.Float()
    cpu_free = odm.Float()
    memory_total = odm.Float()
    cpu_total = odm.Float()


# Scaler heartbeats aren't sent
# @odm.model()
# class Heartbeat(odm.Model):
#     instances = odm.Integer()
#     metrics = odm.Compound(Metrics)
#     status = odm.Mapping(odm.Compound(Status))
#
# @odm.model()
# class ScalerMessage(odm.Model):
#     msg = odm.Compound(Heartbeat)
#     msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
#     msg_type = odm.Enum(values=MSG_TYPES, default="ScalerHeartbeat")
#     sender = odm.Keyword()
