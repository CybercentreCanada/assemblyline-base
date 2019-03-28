from assemblyline import odm

MSG_TYPES = {"AlerterHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.alerter_heartbeat.AlerterMessage"


@odm.model()
class Queues(odm.Model):
    alert = odm.Integer()


@odm.model()
class Metrics(odm.Model):
    created = odm.Integer()
    error = odm.Integer()
    received = odm.Integer()
    updated = odm.Integer()

@odm.model()
class Heartbeat(odm.Model):
    instances = odm.Integer()
    metrics = odm.Compound(Metrics)
    queues = odm.Compound(Queues)


@odm.model()
class AlerterMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="AlerterHeartbeat")
    sender = odm.Keyword()
