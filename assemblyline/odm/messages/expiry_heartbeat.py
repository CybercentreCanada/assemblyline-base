from assemblyline import odm

MSG_TYPES = {"ExpiryHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.alerter_heartbeat.ExpiryMessage"


@odm.model()
class Metrics(odm.Model):
    alert = odm.Integer()
    cached_file = odm.Integer()
    emptyresult = odm.Integer()
    error = odm.Integer()
    file = odm.Integer()
    filescore = odm.Integer()
    result = odm.Integer()
    submission = odm.Integer()
    submission_tree = odm.Integer()
    submission_tags = odm.Integer()
    submission_attack = odm.Integer()

@odm.model()
class Heartbeat(odm.Model):
    instances = odm.Integer()
    metrics = odm.Compound(Metrics)
    queues = odm.Compound(Metrics)


@odm.model()
class ExpiryMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ExpiryHeartbeat")
    sender = odm.Keyword()
